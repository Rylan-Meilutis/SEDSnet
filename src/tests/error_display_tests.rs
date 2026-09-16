use crate::TelemetryError;
use std::sync::Arc;

#[test]
fn every_error_formats_without_recursing() {
    use TelemetryError::*;
    let errors = [
        GenericError(None),
        GenericError(Some(Arc::from("test error"))),
        InvalidType,
        SizeMismatch {
            expected: 1,
            got: 4,
        },
        SizeMismatchError,
        EmptyEndpoints,
        TimestampInvalid,
        MissingPayload,
        HandlerError("handler failed"),
        BadArg,
        PermissionDenied,
        Pack("pack failed"),
        Unpack("unpack failed"),
        Io("no discovered route"),
        InvalidUtf8,
        TypeMismatch {
            expected: 1,
            got: 4,
        },
        InvalidLinkId("missing side"),
        PacketTooLarge("queue limit"),
    ];
    for error in errors {
        assert_eq!(error.to_string(), format!("{error:?}"));
        assert_eq!(
            format!("send failed: {error}"),
            format!("send failed: {error:?}")
        );
    }
}
