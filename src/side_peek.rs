//! Classify the frames a router puts on a packed side without its state.
//!
//! An application that filters a side's egress below the router (for example
//! a station that, while listening, lets only acknowledgements, its discovery
//! leave or an ABORT through) sees canonical frames, side-transport FULL and
//! compact frames, and chunks. Compact frames name a header template instead
//! of carrying the type, and only a chunk's first fragment carries the inner
//! frame's header. [`SideFramePeeker`] learns template and chunk identities
//! from the frames it is shown, in transmit order, and classifies each one.
//! Show it every frame the side emits, including those the filter drops.

use crate::DataType;
use crate::side_transport::{
    SIDE_TRANSPORT_KIND_CHUNK, SIDE_TRANSPORT_KIND_COMPACT, SIDE_TRANSPORT_KIND_FULL,
    read_uleb128_local, side_frame_kind,
};
use crate::wire_format;
use alloc::collections::VecDeque;

/// How the frame was framed on the side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideFrameKind {
    /// A canonical packed frame.
    Canonical,
    /// A side-transport frame carrying a full canonical frame.
    Full,
    /// A side-transport compact frame (its type comes from a learned template).
    Compact,
    /// A fragment of a larger frame.
    Chunk,
}

/// A classified side frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideFrameInfo {
    pub ty: DataType,
    pub kind: SideFrameKind,
    /// The reliable header flags, when the frame's header was visible (not for
    /// compact frames or later chunks).
    pub reliable_flags: Option<u8>,
}

const MAX_REMEMBERED: usize = 64;

/// Learns a side's header templates and chunk transfers from its frames.
#[derive(Debug, Default)]
pub struct SideFramePeeker {
    header_templates: bool,
    templates: VecDeque<(u32, DataType)>,
    chunks: VecDeque<(u32, SideFrameInfo)>,
}

fn remember<T: Copy>(list: &mut VecDeque<(u32, T)>, id: u32, value: T) {
    list.retain(|(known, _)| *known != id);
    if list.len() >= MAX_REMEMBERED {
        list.pop_front();
    }
    list.push_back((id, value));
}

fn lookup<T: Copy>(list: &VecDeque<(u32, T)>, id: u32) -> Option<T> {
    list.iter().rev().find(|(known, _)| *known == id).map(|(_, value)| *value)
}

/// Whether `bytes` is a side-transport frame (FULL, COMPACT or CHUNK) rather
/// than a canonical frame or a compact bundle. The first byte decides: no
/// check of the rest is made.
pub fn is_side_transport_frame(bytes: &[u8]) -> bool {
    matches!(
        side_frame_kind(bytes),
        Some(SIDE_TRANSPORT_KIND_FULL | SIDE_TRANSPORT_KIND_COMPACT | SIDE_TRANSPORT_KIND_CHUNK)
    )
}

/// Whether `bytes` is a side-transport chunk (a fragment of a larger frame).
pub fn is_side_transport_chunk(bytes: &[u8]) -> bool {
    bytes.first() == Some(&SIDE_TRANSPORT_KIND_CHUNK)
}

/// One fragment of a chunked side frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideChunk<'a> {
    /// Transfer id shared by every chunk of the frame (16-bit content id).
    pub transfer: u16,
    pub index: u16,
    pub total: u16,
    /// The fragment's bytes of the chunked frame.
    pub payload: &'a [u8],
}

/// A chunk frame's header and fragment, when `bytes` is a chunk whose CRC32
/// is intact.
pub fn side_chunk(bytes: &[u8]) -> Option<SideChunk<'_>> {
    let body = crate::side_transport::checked_chunk_body(bytes).ok()?;
    let (transfer, index, total, header) = crate::side_transport::parse_chunk_header(body).ok()?;
    Some(SideChunk { transfer: transfer as u16, index, total, payload: &body[header..] })
}

/// A chunk frame's header and fragment without checking its CRC32 (for
/// frames this node built itself): the fragment excludes the trailing CRC.
pub fn side_chunk_unchecked(bytes: &[u8]) -> Option<SideChunk<'_>> {
    if !is_side_transport_chunk(bytes) || bytes.len() < 1 + wire_format::CRC32_BYTES + 4 {
        return None;
    }
    let body = &bytes[1..bytes.len() - wire_format::CRC32_BYTES];
    let (transfer, index, total, header) = crate::side_transport::parse_chunk_header(body).ok()?;
    Some(SideChunk { transfer: transfer as u16, index, total, payload: &body[header..] })
}

/// A FULL template frame's template id and the canonical frame it carries
/// (with its own CRC32), when `bytes` is a FULL frame whose CRC32 is intact.
pub fn side_full_frame(bytes: &[u8]) -> Option<(u32, alloc::vec::Vec<u8>)> {
    let (template, _, _, raw) = crate::side_transport::decode_full_frame(bytes).ok()?;
    Some((template, raw.to_vec()))
}

/// The template id a FULL or COMPACT frame names (without checking its CRC).
pub fn side_template_id(bytes: &[u8]) -> Option<u32> {
    matches!(side_frame_kind(bytes), Some(SIDE_TRANSPORT_KIND_FULL | SIDE_TRANSPORT_KIND_COMPACT))
        .then(|| crate::side_transport::template_id_and_gen(bytes).ok().map(|(id, _, _)| id))
        .flatten()
}

/// The start of the canonical frame inside the first bytes of a FULL frame
/// (for example a chunk's first fragment): `bytes` after the kind, template
/// id and base delta.
pub fn side_full_frame_prefix(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.first() != Some(&SIDE_TRANSPORT_KIND_FULL) {
        return None;
    }
    let (_, _, mut off) = crate::side_transport::template_id_and_gen(bytes).ok()?;
    read_uleb128_local(bytes, &mut off).ok()?;
    bytes.get(off..)
}

/// Whether `bytes` is a FULL template frame (first byte).
pub fn is_side_full_frame(bytes: &[u8]) -> bool {
    bytes.first() == Some(&SIDE_TRANSPORT_KIND_FULL)
}

/// Whether `bytes` is a COMPACT template frame (first byte).
pub fn is_side_compact_frame(bytes: &[u8]) -> bool {
    side_frame_kind(bytes) == Some(SIDE_TRANSPORT_KIND_COMPACT)
}

/// A frame's type without side state: canonical frames, side-transport FULL
/// frames (templated or not) and a chunk's first fragment. A compact frame or
/// a later fragment needs a [`SideFramePeeker`] that saw its template.
pub fn peek_side_frame_type(bytes: &[u8]) -> Option<DataType> {
    SideFramePeeker::new(false).peek(bytes).map(|info| info.ty)
}

impl SideFramePeeker {
    /// `header_templates`: the side was configured with header templates
    /// (`SideOptions::header_template_enabled`, e.g. `with_small_packet_transport`).
    pub fn new(header_templates: bool) -> Self {
        Self { header_templates, ..Self::default() }
    }

    /// Classify one frame the side emitted; None when it cannot be read.
    pub fn peek(&mut self, bytes: &[u8]) -> Option<SideFrameInfo> {
        self.peek_frame(bytes, true)
    }

    /// `complete`: `bytes` is a whole frame (its checks can be run), not the
    /// first fragment of one.
    fn peek_frame(&mut self, bytes: &[u8], complete: bool) -> Option<SideFrameInfo> {
        let read = |raw: &[u8]| -> Option<wire_format::TelemetryFrameInfo> {
            if complete {
                wire_format::peek_frame_info(raw).ok()
            } else {
                wire_format::peek_frame_info_inner(raw).ok()
            }
        };
        let Some(kind) = side_frame_kind(bytes) else {
            let info = read(bytes)?;
            return Some(SideFrameInfo {
                ty: info.envelope.ty,
                kind: SideFrameKind::Canonical,
                reliable_flags: info.reliable.map(|header| header.flags),
            });
        };
        match kind {
            SIDE_TRANSPORT_KIND_FULL => {
                // Kind, template id/generation and base delta precede the
                // canonical data.
                let (template, info) = if complete {
                    let (template, _, _, raw) = crate::side_transport::decode_full_frame(bytes).ok()?;
                    (template, wire_format::peek_frame_info(&raw).ok()?)
                } else {
                    let (template, _, mut off) = crate::side_transport::template_id_and_gen(bytes).ok()?;
                    read_uleb128_local(bytes, &mut off).ok()?;
                    // A fragment ends mid-frame: no CRC to strip or check.
                    let mut data = bytes.get(off..)?.to_vec();
                    data.extend_from_slice(&[0; 4]);
                    (template, wire_format::peek_frame_info_unchecked(&data).ok()?)
                };
                if self.header_templates {
                    remember(&mut self.templates, template, info.envelope.ty);
                }
                Some(SideFrameInfo {
                    ty: info.envelope.ty,
                    kind: SideFrameKind::Full,
                    reliable_flags: info.reliable.map(|header| header.flags),
                })
            }
            SIDE_TRANSPORT_KIND_COMPACT => {
                let (template, _, _) = crate::side_transport::template_id_and_gen(bytes).ok()?;
                Some(SideFrameInfo {
                    ty: lookup(&self.templates, template)?,
                    kind: SideFrameKind::Compact,
                    reliable_flags: None,
                })
            }
            SIDE_TRANSPORT_KIND_CHUNK if complete => {
                let body = crate::side_transport::checked_chunk_body(bytes).ok()?;
                let (transfer, index, _total, header_len) =
                    crate::side_transport::parse_chunk_header(body).ok()?;
                if index == 0 {
                    let inner = self.peek_frame(&body[header_len..], false)?;
                    let info = SideFrameInfo { kind: SideFrameKind::Chunk, ..inner };
                    remember(&mut self.chunks, transfer, info);
                    Some(info)
                } else {
                    lookup(&self.chunks, transfer).map(|info| SideFrameInfo { reliable_flags: None, ..info })
                }
            }
            _ => None,
        }
    }
}
