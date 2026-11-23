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
    SIDE_TRANSPORT_KIND_CHUNK, SIDE_TRANSPORT_KIND_COMPACT, SIDE_TRANSPORT_KIND_COMPACT_DELTA,
    SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP, SIDE_TRANSPORT_KIND_FULL, SIDE_TRANSPORT_MAGIC,
    parse_side_transport_wrapper, read_uleb128_local,
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
        if !bytes.starts_with(SIDE_TRANSPORT_MAGIC) {
            let info = wire_format::peek_frame_info_unchecked(bytes).ok()?;
            return Some(SideFrameInfo {
                ty: info.envelope.ty,
                kind: SideFrameKind::Canonical,
                reliable_flags: info.reliable.map(|header| header.flags),
            });
        }
        let (kind, body) = parse_side_transport_wrapper(bytes).ok()??;
        self.peek_body(kind, body, true)
    }

    fn peek_body(&mut self, kind: u8, body: &[u8], complete: bool) -> Option<SideFrameInfo> {
        match kind {
            SIDE_TRANSPORT_KIND_FULL => {
                // A templated side prefixes the template ID. A complete frame
                // is CRC-checked under both readings, so a peeker built for
                // the wrong side kind still reads it; a fragment uses the
                // configured reading.
                let read = |off: usize| -> Option<wire_format::TelemetryFrameInfo> {
                    let raw = body.get(off..)?;
                    if complete { wire_format::peek_frame_info(raw).ok() } else { wire_format::peek_frame_info_inner(raw).ok() }
                };
                let mut prefixed = 0usize;
                let template = read_uleb128_local(body, &mut prefixed).ok().and_then(|id| u32::try_from(id).ok());
                let (template, info) = if self.header_templates || complete {
                    match (template.and_then(|t| read(prefixed).map(|i| (Some(t), i))), self.header_templates) {
                        (Some(found), true) => found,
                        (found, _) => match read(0) {
                            Some(info) => (None, info),
                            None => found?,
                        },
                    }
                } else {
                    (None, read(0)?)
                };
                if let Some(template) = template {
                    remember(&mut self.templates, template, info.envelope.ty);
                }
                Some(SideFrameInfo {
                    ty: info.envelope.ty,
                    kind: SideFrameKind::Full,
                    reliable_flags: info.reliable.map(|header| header.flags),
                })
            }
            SIDE_TRANSPORT_KIND_COMPACT
            | SIDE_TRANSPORT_KIND_COMPACT_DELTA
            | SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP => {
                let mut off = 1usize;
                let template = u32::try_from(read_uleb128_local(body, &mut off).ok()?).ok()?;
                Some(SideFrameInfo {
                    ty: lookup(&self.templates, template)?,
                    kind: SideFrameKind::Compact,
                    reliable_flags: None,
                })
            }
            SIDE_TRANSPORT_KIND_CHUNK if complete => {
                let (transfer, index, _total, header_len) =
                    crate::side_transport::parse_chunk_header(body).ok()?;
                if index == 0 {
                    let payload = &body[header_len..];
                    let inner = if payload.starts_with(SIDE_TRANSPORT_MAGIC) && payload.len() > 4 {
                        self.peek_body(payload[3], &payload[4..], false)?
                    } else {
                        let info = wire_format::peek_frame_info_inner(payload).ok()?;
                        SideFrameInfo {
                            ty: info.envelope.ty,
                            kind: SideFrameKind::Canonical,
                            reliable_flags: info.reliable.map(|header| header.flags),
                        }
                    };
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
