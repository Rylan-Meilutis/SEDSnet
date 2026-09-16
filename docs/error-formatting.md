# Error formatting regression

The candidate fixes a recursive `TelemetryError` Display implementation. Calling
`to_string()` inside Display invokes Display again and can overflow the caller
stack whenever an error is logged with `{error}`. The failure is independent of
transport: even a rejected command payload can trigger it. Debug formatting did
not exercise the broken path, which made some error logs appear safe.

Display now delegates directly to derived Debug, retaining the variant and its
details without recursion or an intermediate allocation. Regression coverage
formats every error variant through both Display and ToString. This applies to
host and embedded consumers; it does not increase thread stacks or hide errors.

The triggering GroundStation simulation command also used an inferred i32 where
the schema requires u8. Its command generator is now explicitly byte-typed and
tested independently. Neither change substitutes for route-recovery testing.

Validation: `./build.py test full` passed all nine stages for this candidate,
including 358 Rust/system tests, embedded-schema tests, Python checks, default/
Python/embedded Clippy checks, benchmark smoke tests and an embedded build.
The multibus system fixture now gives nodes unique discovery identities and
waits for learned routes before publishing; it no longer relies on a successful
return from a send that had no discovered destination.
