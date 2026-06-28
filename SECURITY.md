# Security Policy

## Supported Versions

Security fixes are provided for the current `4.x` release line. Older major
versions are not supported unless a separate maintenance branch is announced.

| Version | Supported |
|---------|-----------|
| 4.x.x   | Yes       |
| < 4.0.0 | No        |

## Security Features in v4.x

Security is part of the v4.x networking stack. With the default `cryptography`
feature enabled, data types can declare whether end-to-end payload cryptography
is optional, preferred, or required. Routers can run in `Disabled`,
`RequiredOnly`, `Preferred`, or `ForceAll` E2E modes. Required encrypted data is
rejected when cryptography support is unavailable instead of silently falling
back to plaintext.

Encrypted payloads authenticate selected visible routing/header bytes as
associated data, so payload or authenticated-header tampering fails during
unpack/open. Cryptography providers can be registered from C, Rust, OS crypto
wrappers, hardware crypto, secure elements, or a software fallback key for host
and test deployments.

v4.x also includes compact managed credential helpers for deployments where a
master/root authority issues board credentials and approves session or group
keys. Key trust is still a deployment responsibility: boards need a trusted key
source such as factory-provisioned PSKs, a provisioned root public key, or a
master/root join flow. Without an authenticated key source, an active attacker
can substitute keys before packet authentication starts.

Implementation details are documented in:

- [Usage-Rust](docs/wiki/Usage-Rust.md#managed-variables-and-e2e-payloads)
- [Usage-C-Cpp](docs/wiki/Usage-C-Cpp.md#security-and-cryptography)
- [Usage-Python](docs/wiki/Usage-Python.md#managed-variables-and-e2e-policy)
- [Technical-Wire-Format](docs/wiki/Technical-Wire-Format.md)

## Reporting a Vulnerability

Email rylan@rylanswebsite.com to report a vulnerability.

Please include:

- affected version or commit
- a short description of the issue
- reproduction steps or proof of concept, if available
- expected impact

Do not open a public issue for suspected vulnerabilities until the issue has
been reviewed.
