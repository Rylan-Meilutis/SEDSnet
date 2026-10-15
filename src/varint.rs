//! Bounded ULEB128 decoding using only native-width variable shifts.
use crate::{TelemetryError, TelemetryResult};

// Cortex-M does not have a variable 64-bit shift instruction. Keep the two
// halves separate until the final constant-width join.
#[inline]
pub(crate) fn read_u64(buf: &[u8], off: &mut usize) -> TelemetryResult<u64> {
    #[cfg(target_pointer_width = "32")]
    {
        read_u64_32(buf, off)
    }
    #[cfg(not(target_pointer_width = "32"))]
    {
        let mut value = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            let Some(&byte) = buf.get(*off) else {
                return Err(TelemetryError::Unpack("short read"));
            };
            *off += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if shift == 63 && byte > 1 {
                    return Err(TelemetryError::Unpack("uleb128 too long"));
                }
                return Ok(value);
            }
            shift += 7;
        }
        Err(TelemetryError::Unpack("uleb128 too long"))
    }
}

#[cfg(any(test, target_pointer_width = "32"))]
#[inline(never)]
fn read_u64_32(buf: &[u8], off: &mut usize) -> TelemetryResult<u64> {
    let (mut low, mut high) = (0u32, 0u32);
    for index in 0..10u32 {
        let Some(&byte) = buf.get(*off) else {
            return Err(TelemetryError::Unpack("short read"));
        };
        *off += 1;
        let part = u32::from(byte & 0x7f);
        match index {
            0..=3 => low |= part << (7 * index),
            4 => {
                low |= part << 28;
                high = part >> 4;
            }
            5..=8 => high |= part << (7 * index - 32),
            _ => {
                if byte > 1 {
                    return Err(TelemetryError::Unpack("uleb128 too long"));
                }
                high |= part << 31;
            }
        }
        if byte & 0x80 == 0 {
            return Ok((u64::from(high) << 32) | u64::from(low));
        }
    }
    Err(TelemetryError::Unpack("uleb128 too long"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn encoded(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value % 128) as u8;
            value /= 128;
            out.push(byte | if value != 0 { 128 } else { 0 });
            if value == 0 {
                return out;
            }
        }
    }

    fn roundtrip(value: u64) {
        let mut bytes = alloc::vec![0x55];
        bytes.extend(encoded(value));
        let end = bytes.len();
        bytes.push(0xaa);
        type Reader = fn(&[u8], &mut usize) -> TelemetryResult<u64>;
        for read in [read_u64 as Reader, read_u64_32] {
            let mut offset = 1;
            assert_eq!(read(&bytes, &mut offset).unwrap(), value);
            assert_eq!(offset, end);
            assert_eq!(bytes[offset], 0xaa);
        }
    }

    #[test]
    fn scalar_ids_full_width_timestamps_and_bit_boundaries_roundtrip() {
        for value in 0..=65536 {
            roundtrip(value);
        }
        for bit in 0..64 {
            let value = 1u64 << bit;
            for neighbor in [value - 1, value, value.saturating_add(1)] {
                roundtrip(neighbor);
            }
        }
        roundtrip(u64::MAX);
        let mut random = 0x7812_cdaa_691f_002bu64;
        for _ in 0..100_000 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            roundtrip(random);
        }
    }

    #[test]
    fn truncated_and_overflowing_values_never_wrap_or_read_past_input() {
        type Reader = fn(&[u8], &mut usize) -> TelemetryResult<u64>;
        for read_u64 in [super::read_u64 as Reader, read_u64_32] {
            for size in 0..10 {
                let bytes = alloc::vec![0x80; size];
                let mut offset = 0;
                assert!(matches!(
                    read_u64(&bytes, &mut offset),
                    Err(TelemetryError::Unpack("short read"))
                ));
                assert_eq!(offset, size);
            }
            for last in 2..=255 {
                let mut bytes = alloc::vec![0xff; 9];
                bytes.push(last);
                bytes.push(0x55);
                let mut offset = 0;
                assert!(
                    read_u64(&bytes, &mut offset).is_err(),
                    "overflow byte {last}"
                );
                assert_eq!(offset, 10);
            }
            // Non-minimal zero encodings remain legal, matching the existing wire API.
            let mut bytes = alloc::vec![0x80; 9];
            bytes.push(0);
            assert_eq!(read_u64(&bytes, &mut 0).unwrap(), 0);
        }
    }
}
