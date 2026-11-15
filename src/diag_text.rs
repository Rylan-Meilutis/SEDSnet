//! Formatting-free text for the few router diagnostics that embedded builds
//! emit. `format!`/`{:?}` would link `core::fmt`, the `str` Debug escaper and
//! its Unicode tables (about 10 KB of flash on Cortex-M) for three strings.
//! The output matches the `Debug`/`Display` forms these sites used before;
//! the `matches_core_fmt` tests compare them on hosted builds.

use crate::config::DataEndpoint;
use crate::TelemetryError;
use alloc::string::String;

/// Appends `value` in decimal (`Display` for unsigned integers).
pub(crate) fn push_dec(out: &mut String, value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    let mut rest = value;
    loop {
        at -= 1;
        digits[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for &digit in &digits[at..] {
        out.push(digit as char);
    }
}

/// Appends `value` as lowercase hex, zero-padded to at least `width` digits
/// (`{:0width$x}`).
pub(crate) fn push_hex(out: &mut String, value: u64, width: usize) {
    let mut digits = 1usize;
    while digits < 16 && (value >> (4 * digits)) != 0 {
        digits += 1;
    }
    let digits = digits.max(width.min(16));
    for _ in 16..width {
        out.push('0');
    }
    for index in (0..digits).rev() {
        let nibble = ((value >> (4 * index)) & 0xf) as u8;
        out.push(char::from(if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 }));
    }
}

/// Appends `text` as `str`'s `Debug` form: quoted, with `\\`, `"`, `\t`,
/// `\r`, `\n`, `\0` and other ASCII control characters escaped. Non-ASCII
/// characters are copied unchanged, as `Debug` does for printable ones.
pub(crate) fn push_debug_str(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str("\\u{");
                push_hex(out, c as u64, 0);
                out.push('}');
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends the endpoint's `Debug` form.
pub(crate) fn push_debug_endpoint(out: &mut String, endpoint: DataEndpoint) {
    endpoint.with_debug_name(|name| match name {
        Some(name) => out.push_str(name),
        None => {
            out.push_str("DataEndpoint(");
            push_dec(out, u64::from(endpoint.0));
            out.push(')');
        }
    });
}

fn push_debug_static(out: &mut String, variant: &str, text: &str) {
    out.push_str(variant);
    out.push('(');
    push_debug_str(out, text);
    out.push(')');
}

fn push_debug_sizes(out: &mut String, variant: &str, expected: usize, got: usize) {
    out.push_str(variant);
    out.push_str(" { expected: ");
    push_dec(out, expected as u64);
    out.push_str(", got: ");
    push_dec(out, got as u64);
    out.push_str(" }");
}

/// Appends the derived `Debug` form of `error`.
pub(crate) fn push_debug_error(out: &mut String, error: &TelemetryError) {
    use TelemetryError as E;
    match error {
        E::GenericError(None) => out.push_str("GenericError(None)"),
        E::GenericError(Some(text)) => {
            out.push_str("GenericError(Some(");
            push_debug_str(out, text);
            out.push_str("))");
        }
        E::InvalidType => out.push_str("InvalidType"),
        E::SizeMismatch { expected, got } => push_debug_sizes(out, "SizeMismatch", *expected, *got),
        E::SizeMismatchError => out.push_str("SizeMismatchError"),
        E::EmptyEndpoints => out.push_str("EmptyEndpoints"),
        E::TimestampInvalid => out.push_str("TimestampInvalid"),
        E::MissingPayload => out.push_str("MissingPayload"),
        E::HandlerError(text) => push_debug_static(out, "HandlerError", text),
        E::BadArg => out.push_str("BadArg"),
        E::PermissionDenied => out.push_str("PermissionDenied"),
        E::Pack(text) => push_debug_static(out, "Pack", text),
        E::Unpack(text) => push_debug_static(out, "Unpack", text),
        E::Io(text) => push_debug_static(out, "Io", text),
        E::InvalidUtf8 => out.push_str("InvalidUtf8"),
        E::TypeMismatch { expected, got } => push_debug_sizes(out, "TypeMismatch", *expected, *got),
        E::InvalidLinkId(text) => push_debug_static(out, "InvalidLinkId", text),
        E::PacketTooLarge(text) => push_debug_static(out, "PacketTooLarge", text),
    }
}

/// `format!("Handler for endpoint {:?} failed on device {:?}: {:?}", ..)`
/// for a known endpoint (`Some`) or for an `Option` endpoint (`None` wraps).
pub(crate) fn handler_failed(
    endpoint: Option<DataEndpoint>,
    endpoint_is_option: bool,
    device: &str,
    error: &TelemetryError,
) -> String {
    let mut out = String::new();
    out.push_str("Handler for endpoint ");
    match (endpoint, endpoint_is_option) {
        (Some(ep), false) => push_debug_endpoint(&mut out, ep),
        (Some(ep), true) => {
            out.push_str("Some(");
            push_debug_endpoint(&mut out, ep);
            out.push(')');
        }
        (None, _) => out.push_str("None"),
    }
    out.push_str(" failed on device ");
    push_debug_str(&mut out, device);
    out.push_str(": ");
    push_debug_error(&mut out, error);
    out
}

/// `format!("TX Handler failed on device {:?}: {:?}", device, error)`.
pub(crate) fn tx_handler_failed(device: &str, error: &TelemetryError) -> String {
    let mut out = String::new();
    out.push_str("TX Handler failed on device ");
    push_debug_str(&mut out, device);
    out.push_str(": ");
    push_debug_error(&mut out, error);
    out
}

/// Concatenates `parts` (`format!("{}{}", ..)` for string parts).
pub(crate) fn concat(parts: &[&str]) -> String {
    let mut out = String::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        out.push_str(part);
    }
    out
}

#[cfg(all(test, feature = "std"))]
mod matches_core_fmt {
    use super::*;
    use alloc::format;
    use alloc::sync::Arc;

    fn errors() -> alloc::vec::Vec<TelemetryError> {
        use TelemetryError as E;
        alloc::vec![
            E::GenericError(None),
            E::GenericError(Some(Arc::from("quote \" back \\ tab\t nl\n cr\r nul\0 esc\u{1b} del\u{7f} é ✓"))),
            E::InvalidType,
            E::SizeMismatch { expected: 0, got: usize::MAX },
            E::SizeMismatchError,
            E::EmptyEndpoints,
            E::TimestampInvalid,
            E::MissingPayload,
            E::HandlerError("handler said 'no'"),
            E::BadArg,
            E::PermissionDenied,
            E::Pack("pack"),
            E::Unpack("decompression failed"),
            E::Io("memory pressure"),
            E::InvalidUtf8,
            E::TypeMismatch { expected: 12345, got: 7 },
            E::InvalidLinkId("link"),
            E::PacketTooLarge(""),
        ]
    }

    #[test]
    fn integers() {
        for value in [0u64, 1, 9, 10, 255, 4096, u32::MAX as u64, u64::MAX] {
            let mut out = String::new();
            push_dec(&mut out, value);
            assert_eq!(out, format!("{value}"));
            for width in [0usize, 1, 8, 16, 20] {
                let mut out = String::new();
                push_hex(&mut out, value, width);
                assert_eq!(out, format!("{value:0width$x}"));
            }
        }
    }

    #[test]
    fn error_text() {
        let endpoints = [
            DataEndpoint::TelemetryError,
            DataEndpoint::TimeSync,
            DataEndpoint::Discovery,
            DataEndpoint(0xdead_beef),
        ];
        for device in ["RF", "", "dev \"x\"\n"] {
            for error in errors() {
                let mut out = String::new();
                push_debug_error(&mut out, &error);
                assert_eq!(out, format!("{error:?}"));
                assert_eq!(
                    tx_handler_failed(device, &error),
                    format!("TX Handler failed on device {:?}: {:?}", device, error)
                );
                for endpoint in endpoints {
                    assert_eq!(
                        handler_failed(Some(endpoint), false, device, &error),
                        format!("Handler for endpoint {:?} failed on device {:?}: {:?}", endpoint, device, error)
                    );
                    let option = Some(endpoint);
                    assert_eq!(
                        handler_failed(option, true, device, &error),
                        format!("Handler for endpoint {:?} failed on device {:?}: {:?}", option, device, error)
                    );
                }
                let none: Option<DataEndpoint> = None;
                assert_eq!(
                    handler_failed(none, true, device, &error),
                    format!("Handler for endpoint {:?} failed on device {:?}: {:?}", none, device, error)
                );
            }
        }
    }
}
