//! Level-1 zstd frames must not depend on the opt-in `zstd-lean` feature or on
//! which verified zstd release (1.5.7 or 1.6.0) is linked.
//!
//! The same digest is asserted with and without the feature and for both
//! releases, so a build that omits zstd's LDM/superblock objects is proven to
//! emit byte-identical frames for SEDSnet's own compression call, and nodes
//! built against either release exchange identical frames. Inputs cover the
//! tiny-block path that calls the LDM skip helpers, ordinary telemetry sizes,
//! and multi-block frames beyond zstd's 128 KiB block size.
//!
//! `fixtures/zstd-1.5.7-reference-frames.bin` holds frames written by the
//! reference zstd 1.5.7 command-line tool (`zstd -q -c --check -1` and `-19`)
//! for [`reference_inputs`], so whichever zstd this build links must decode
//! frames from an independent 1.5.7 encoder, including checksummed and
//! higher-level frames SEDSnet itself never writes.

/// FNV-1a over every (input length, frame) pair.
const GOLDEN_FRAMES_FNV1A: u64 = 0xbfd9_3d78_ad37_443c;

fn corpus() -> Vec<Vec<u8>> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut inputs = Vec::new();
    for len in [
        1usize, 2, 3, 5, 6, 7, 8, 9, 16, 29, 30, 31, 64, 100, 128, 255, 512, 1024, 4096, 8192,
        65_536, 200_000, 300_001,
    ] {
        // Telemetry-like: slowly varying little-endian samples with noise.
        let mut telemetry = Vec::with_capacity(len);
        let mut sample = 1000i32;
        while telemetry.len() < len {
            sample += (next() % 7) as i32 - 3;
            telemetry.extend_from_slice(&sample.to_le_bytes());
        }
        telemetry.truncate(len);
        inputs.push(telemetry);
        // Repetitive text and random bytes.
        inputs.push(
            b"FLIGHT_STATE,ASCENT,"
                .iter()
                .copied()
                .cycle()
                .take(len)
                .collect(),
        );
        inputs.push((0..len).map(|_| next() as u8).collect());
    }
    inputs
}

fn fnv1a(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

#[test]
fn level_one_frames_match_golden_digest_and_roundtrip() {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for input in corpus() {
        let mut frame = vec![0u8; zstd_safe::compress_bound(input.len())];
        let written = zstd_safe::compress(&mut frame[..], &input, 1).expect("compress");
        frame.truncate(written);
        fnv1a(&mut hash, &(input.len() as u64).to_le_bytes());
        fnv1a(&mut hash, &frame);

        let mut output = vec![0u8; input.len()];
        let read = zstd_safe::decompress(&mut output[..], &frame).expect("decompress");
        assert_eq!(read, input.len());
        assert_eq!(output, input);
    }
    assert_eq!(
        hash, GOLDEN_FRAMES_FNV1A,
        "level-1 zstd frames changed: {hash:#018x}"
    );
}

/// Every corpus entry up to 8 KiB, plus the repetitive text beyond zstd's
/// 128 KiB block size: the inputs of the reference-frame fixture.
fn reference_inputs() -> Vec<Vec<u8>> {
    corpus()
        .into_iter()
        .enumerate()
        .filter(|(index, input)| input.len() <= 8192 || index % 3 == 1)
        .map(|(_, input)| input)
        .collect()
}

#[test]
fn linked_zstd_is_a_verified_release() {
    assert!(
        matches!(zstd_safe::version_number(), 10507 | 10600),
        "unverified zstd {}",
        zstd_safe::version_number()
    );
}

#[test]
fn reference_zstd_1_5_7_frames_decode() {
    let mut frames = &include_bytes!("fixtures/zstd-1.5.7-reference-frames.bin")[..];
    for input in reference_inputs() {
        // Each input was written at level 1 and then at level 19.
        for _level in [1, 19] {
            let size = zstd_safe::find_frame_compressed_size(frames).expect("frame size");
            let (frame, rest) = frames.split_at(size);
            frames = rest;
            let mut output = vec![0u8; input.len()];
            let read = zstd_safe::decompress(&mut output[..], frame).expect("decompress");
            assert_eq!(read, input.len());
            assert_eq!(output, input);
        }
    }
    assert!(frames.is_empty(), "{} unread fixture bytes", frames.len());
}
