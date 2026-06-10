//! Feature-gated cryptography shim interfaces.
//!
//! Registered C/Rust shims are preferred so std builds can use OS crypto APIs
//! and embedded builds can use hardware accelerators or secure elements. A
//! small software fallback is also available when a key is registered.

use crate::{TelemetryError, TelemetryResult};

const SOFTWARE_KEY_SLOTS: usize = 8;
const SOFTWARE_KEY_MIN_LEN: usize = 16;
const SOFTWARE_TAG_LEN: usize = 16;
pub const MANAGED_CREDENTIAL_LEN: usize = 80;
const MANAGED_CREDENTIAL_BODY_LEN: usize = 48;
const MANAGED_CREDENTIAL_MAGIC: &[u8; 8] = b"SEDSCR1\0";

/// Rust-side AEAD-like payload crypto shim.
///
/// `key_id` is application-defined. `nonce` and `aad` are passed through by the
/// caller; the shim is responsible for enforcing the algorithm's expected sizes.
pub trait CryptoShim: Sync {
    fn seal(
        &self,
        key_id: u32,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) -> TelemetryResult<(usize, usize)>;

    fn open(
        &self,
        key_id: u32,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        plaintext_out: &mut [u8],
    ) -> TelemetryResult<usize>;
}

/// Use a Rust shim directly without any C ABI involvement.
pub fn seal_with<S: CryptoShim + ?Sized>(
    shim: &S,
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8],
) -> TelemetryResult<(usize, usize)> {
    shim.seal(key_id, nonce, aad, plaintext, ciphertext_out, tag_out)
}

/// Use a Rust shim directly without any C ABI involvement.
pub fn open_with<S: CryptoShim + ?Sized>(
    shim: &S,
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext_out: &mut [u8],
) -> TelemetryResult<usize> {
    shim.open(key_id, nonce, aad, ciphertext, tag, plaintext_out)
}

pub type CSealFn = unsafe extern "C" fn(
    key_id: u32,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_cap: usize,
    ciphertext_len_out: *mut usize,
    tag_out: *mut u8,
    tag_cap: usize,
    tag_len_out: *mut usize,
    user: *mut core::ffi::c_void,
) -> i32;

pub type COpenFn = unsafe extern "C" fn(
    key_id: u32,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    tag_len: usize,
    plaintext_out: *mut u8,
    plaintext_cap: usize,
    plaintext_len_out: *mut usize,
    user: *mut core::ffi::c_void,
) -> i32;

#[derive(Clone, Copy)]
pub struct CCryptoShim {
    pub seal: Option<CSealFn>,
    pub open: Option<COpenFn>,
    pub user: *mut core::ffi::c_void,
}

static mut C_SHIM: CCryptoShim = CCryptoShim {
    seal: None,
    open: None,
    user: core::ptr::null_mut(),
};

static mut RUST_SHIM: Option<&'static dyn CryptoShim> = None;

#[derive(Clone, Copy)]
struct SoftwareKey {
    key_id: u32,
    key: [u8; 32],
}

#[derive(Clone, Copy)]
struct SoftwareKeyring {
    keys: [Option<SoftwareKey>; SOFTWARE_KEY_SLOTS],
}

impl SoftwareKeyring {
    const fn new() -> Self {
        Self {
            keys: [None; SOFTWARE_KEY_SLOTS],
        }
    }

    fn is_registered(&self) -> bool {
        self.keys.iter().any(Option::is_some)
    }

    fn get(&self, key_id: u32) -> Option<[u8; 32]> {
        self.keys
            .iter()
            .flatten()
            .find(|key| key.key_id == key_id)
            .map(|key| key.key)
    }

    fn register(&mut self, key_id: u32, raw_key: &[u8]) -> TelemetryResult<()> {
        if raw_key.len() < SOFTWARE_KEY_MIN_LEN {
            return Err(TelemetryError::BadArg);
        }
        let key = normalize_software_key(raw_key);
        if let Some(slot) = self
            .keys
            .iter_mut()
            .find(|slot| slot.map(|key| key.key_id) == Some(key_id))
        {
            *slot = Some(SoftwareKey { key_id, key });
            return Ok(());
        }
        if let Some(slot) = self.keys.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(SoftwareKey { key_id, key });
            return Ok(());
        }
        Err(TelemetryError::SizeMismatchError)
    }
}

static mut SOFTWARE_KEYS: SoftwareKeyring = SoftwareKeyring::new();

/// Register a C callback shim. This should be called during board startup
/// before concurrent router/relay work begins.
pub fn register_c_crypto_shim(shim: CCryptoShim) {
    unsafe {
        core::ptr::addr_of_mut!(C_SHIM).write(shim);
    }
}

pub fn clear_c_crypto_shim() {
    register_c_crypto_shim(CCryptoShim {
        seal: None,
        open: None,
        user: core::ptr::null_mut(),
    });
}

pub fn c_crypto_shim_registered() -> bool {
    let shim = unsafe { core::ptr::addr_of!(C_SHIM).read() };
    shim.seal.is_some() && shim.open.is_some()
}

/// Register a Rust crypto shim for process-wide router/relay E2E traffic.
///
/// Registered shims are preferred over the software fallback. In std builds the
/// shim can wrap OS crypto APIs; in embedded builds it can wrap hardware crypto
/// or a secure element. Call during startup before concurrent router work.
pub fn register_rust_crypto_shim(shim: &'static dyn CryptoShim) {
    unsafe {
        core::ptr::addr_of_mut!(RUST_SHIM).write(Some(shim));
    }
}

pub fn clear_rust_crypto_shim() {
    unsafe {
        core::ptr::addr_of_mut!(RUST_SHIM).write(None);
    }
}

pub fn rust_crypto_shim_registered() -> bool {
    unsafe { core::ptr::addr_of!(RUST_SHIM).read().is_some() }
}

/// Register a software fallback key for `key_id`.
///
/// The fallback uses HMAC-SHA256 to derive a stream and authenticate the
/// ciphertext. Prefer OS/hardware shims when they are available; this path keeps
/// encrypted traffic functional when no accelerator or OS provider is present.
pub fn register_software_key(key_id: u32, key: &[u8]) -> TelemetryResult<()> {
    let mut keyring = unsafe { core::ptr::addr_of!(SOFTWARE_KEYS).read() };
    keyring.register(key_id, key)?;
    unsafe {
        core::ptr::addr_of_mut!(SOFTWARE_KEYS).write(keyring);
    }
    Ok(())
}

pub fn clear_software_keys() {
    unsafe {
        core::ptr::addr_of_mut!(SOFTWARE_KEYS).write(SoftwareKeyring::new());
    }
}

pub fn software_crypto_available() -> bool {
    unsafe { core::ptr::addr_of!(SOFTWARE_KEYS).read().is_registered() }
}

pub fn registered_crypto_available() -> bool {
    c_crypto_shim_registered() || rust_crypto_shim_registered() || software_crypto_available()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedCredential {
    pub subject_id: u64,
    pub key_id: u32,
    pub epoch: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub permissions: u32,
}

/// Issue a compact master-signed credential.
///
/// This is a low-bandwidth alternative to user-managed cert files. Devices still
/// need a provisioned root key or pinned master identity to verify credentials.
pub fn issue_managed_credential(
    root_key: &[u8],
    credential: ManagedCredential,
    out: &mut [u8],
) -> TelemetryResult<usize> {
    if root_key.len() < SOFTWARE_KEY_MIN_LEN || out.len() < MANAGED_CREDENTIAL_LEN {
        return Err(TelemetryError::BadArg);
    }
    write_managed_credential_body(credential, &mut out[..MANAGED_CREDENTIAL_BODY_LEN]);
    let key = normalize_software_key(root_key);
    let tag = hmac_sha256(
        &key,
        &[
            b"SEDS-MASTER-CREDENTIAL",
            &out[..MANAGED_CREDENTIAL_BODY_LEN],
        ],
    );
    out[MANAGED_CREDENTIAL_BODY_LEN..MANAGED_CREDENTIAL_LEN].copy_from_slice(&tag);
    Ok(MANAGED_CREDENTIAL_LEN)
}

/// Verify a compact master-signed credential and check its validity window.
pub fn verify_managed_credential(
    root_key: &[u8],
    bytes: &[u8],
    now_ms: u64,
) -> TelemetryResult<ManagedCredential> {
    if root_key.len() < SOFTWARE_KEY_MIN_LEN || bytes.len() != MANAGED_CREDENTIAL_LEN {
        return Err(TelemetryError::BadArg);
    }
    let credential = read_managed_credential_body(&bytes[..MANAGED_CREDENTIAL_BODY_LEN])?;
    if now_ms < credential.not_before_ms || now_ms > credential.not_after_ms {
        return Err(TelemetryError::HandlerError("credential expired"));
    }
    let key = normalize_software_key(root_key);
    let expected = hmac_sha256(
        &key,
        &[
            b"SEDS-MASTER-CREDENTIAL",
            &bytes[..MANAGED_CREDENTIAL_BODY_LEN],
        ],
    );
    if !constant_time_eq(
        &bytes[MANAGED_CREDENTIAL_BODY_LEN..MANAGED_CREDENTIAL_LEN],
        &expected,
    ) {
        return Err(TelemetryError::HandlerError("credential signature"));
    }
    Ok(credential)
}

pub fn seal_with_registered_c_shim(
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8],
) -> TelemetryResult<(usize, usize)> {
    let shim = unsafe { core::ptr::addr_of!(C_SHIM).read() };
    let Some(seal) = shim.seal else {
        return Err(TelemetryError::BadArg);
    };
    let mut ciphertext_len = 0usize;
    let mut tag_len = 0usize;
    let status = unsafe {
        seal(
            key_id,
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext_out.as_mut_ptr(),
            ciphertext_out.len(),
            &mut ciphertext_len,
            tag_out.as_mut_ptr(),
            tag_out.len(),
            &mut tag_len,
            shim.user,
        )
    };
    if status != 0 {
        return Err(TelemetryError::HandlerError("crypto seal"));
    }
    if ciphertext_len > ciphertext_out.len() || tag_len > tag_out.len() {
        return Err(TelemetryError::SizeMismatchError);
    }
    Ok((ciphertext_len, tag_len))
}

pub fn open_with_registered_c_shim(
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext_out: &mut [u8],
) -> TelemetryResult<usize> {
    let shim = unsafe { core::ptr::addr_of!(C_SHIM).read() };
    let Some(open) = shim.open else {
        return Err(TelemetryError::BadArg);
    };
    let mut plaintext_len = 0usize;
    let status = unsafe {
        open(
            key_id,
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            tag.as_ptr(),
            tag.len(),
            plaintext_out.as_mut_ptr(),
            plaintext_out.len(),
            &mut plaintext_len,
            shim.user,
        )
    };
    if status != 0 {
        return Err(TelemetryError::HandlerError("crypto open"));
    }
    if plaintext_len > plaintext_out.len() {
        return Err(TelemetryError::SizeMismatchError);
    }
    Ok(plaintext_len)
}

pub fn seal_with_registered_crypto(
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8],
) -> TelemetryResult<(usize, usize)> {
    if c_crypto_shim_registered() {
        return seal_with_registered_c_shim(key_id, nonce, aad, plaintext, ciphertext_out, tag_out);
    }
    if let Some(shim) = unsafe { core::ptr::addr_of!(RUST_SHIM).read() } {
        return seal_with(shim, key_id, nonce, aad, plaintext, ciphertext_out, tag_out);
    }
    seal_with_software_key(key_id, nonce, aad, plaintext, ciphertext_out, tag_out)
}

pub fn open_with_registered_crypto(
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext_out: &mut [u8],
) -> TelemetryResult<usize> {
    if c_crypto_shim_registered() {
        return open_with_registered_c_shim(key_id, nonce, aad, ciphertext, tag, plaintext_out);
    }
    if let Some(shim) = unsafe { core::ptr::addr_of!(RUST_SHIM).read() } {
        return open_with(shim, key_id, nonce, aad, ciphertext, tag, plaintext_out);
    }
    open_with_software_key(key_id, nonce, aad, ciphertext, tag, plaintext_out)
}

fn seal_with_software_key(
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8],
) -> TelemetryResult<(usize, usize)> {
    if ciphertext_out.len() < plaintext.len() || tag_out.len() < SOFTWARE_TAG_LEN {
        return Err(TelemetryError::SizeMismatchError);
    }
    let key = software_key_for(key_id)?;
    apply_hmac_stream(&key, key_id, nonce, aad, plaintext, ciphertext_out);
    let tag = software_tag(&key, key_id, nonce, aad, &ciphertext_out[..plaintext.len()]);
    tag_out[..SOFTWARE_TAG_LEN].copy_from_slice(&tag[..SOFTWARE_TAG_LEN]);
    Ok((plaintext.len(), SOFTWARE_TAG_LEN))
}

fn open_with_software_key(
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext_out: &mut [u8],
) -> TelemetryResult<usize> {
    if plaintext_out.len() < ciphertext.len() || tag.len() != SOFTWARE_TAG_LEN {
        return Err(TelemetryError::SizeMismatchError);
    }
    let key = software_key_for(key_id)?;
    let expected = software_tag(&key, key_id, nonce, aad, ciphertext);
    if !constant_time_eq(tag, &expected[..SOFTWARE_TAG_LEN]) {
        return Err(TelemetryError::HandlerError("crypto open"));
    }
    apply_hmac_stream(&key, key_id, nonce, aad, ciphertext, plaintext_out);
    Ok(ciphertext.len())
}

fn software_key_for(key_id: u32) -> TelemetryResult<[u8; 32]> {
    unsafe { core::ptr::addr_of!(SOFTWARE_KEYS).read() }
        .get(key_id)
        .ok_or(TelemetryError::BadArg)
}

fn write_managed_credential_body(credential: ManagedCredential, out: &mut [u8]) {
    out[..8].copy_from_slice(MANAGED_CREDENTIAL_MAGIC);
    out[8..16].copy_from_slice(&credential.subject_id.to_le_bytes());
    out[16..20].copy_from_slice(&credential.key_id.to_le_bytes());
    out[20..28].copy_from_slice(&credential.epoch.to_le_bytes());
    out[28..36].copy_from_slice(&credential.not_before_ms.to_le_bytes());
    out[36..44].copy_from_slice(&credential.not_after_ms.to_le_bytes());
    out[44..48].copy_from_slice(&credential.permissions.to_le_bytes());
}

fn read_managed_credential_body(bytes: &[u8]) -> TelemetryResult<ManagedCredential> {
    if bytes.len() != MANAGED_CREDENTIAL_BODY_LEN || &bytes[..8] != MANAGED_CREDENTIAL_MAGIC {
        return Err(TelemetryError::BadArg);
    }
    Ok(ManagedCredential {
        subject_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        key_id: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        epoch: u64::from_le_bytes(bytes[20..28].try_into().unwrap()),
        not_before_ms: u64::from_le_bytes(bytes[28..36].try_into().unwrap()),
        not_after_ms: u64::from_le_bytes(bytes[36..44].try_into().unwrap()),
        permissions: u32::from_le_bytes(bytes[44..48].try_into().unwrap()),
    })
}

fn normalize_software_key(raw_key: &[u8]) -> [u8; 32] {
    if raw_key.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(raw_key);
        key
    } else {
        Sha256::digest(raw_key)
    }
}

fn apply_hmac_stream(
    key: &[u8; 32],
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    output: &mut [u8],
) {
    let key_id_bytes = key_id.to_le_bytes();
    let mut counter = 0u64;
    let mut offset = 0usize;
    while offset < input.len() {
        let counter_bytes = counter.to_le_bytes();
        let block = hmac_sha256(
            key,
            &[
                b"SEDS-HMAC-STREAM",
                &key_id_bytes,
                nonce,
                aad,
                &counter_bytes,
            ],
        );
        let remaining = input.len() - offset;
        let take = remaining.min(block.len());
        for idx in 0..take {
            output[offset + idx] = input[offset + idx] ^ block[idx];
        }
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

fn software_tag(
    key: &[u8; 32],
    key_id: u32,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 32] {
    let key_id_bytes = key_id.to_le_bytes();
    hmac_sha256(
        key,
        &[b"SEDS-HMAC-TAG", &key_id_bytes, nonce, aad, ciphertext],
    )
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for idx in 0..a.len() {
        diff |= a[idx] ^ b[idx];
    }
    diff == 0
}

fn hmac_sha256(key: &[u8; 32], chunks: &[&[u8]]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for idx in 0..key.len() {
        ipad[idx] ^= key[idx];
        opad[idx] ^= key[idx];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    for chunk in chunks {
        inner.update(chunk);
    }
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    len_bits: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            len_bits: 0,
        }
    }

    fn digest(input: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }

    fn update(&mut self, mut input: &[u8]) {
        self.len_bits = self
            .len_bits
            .wrapping_add((input.len() as u64).wrapping_mul(8));
        if self.buffer_len > 0 {
            let take = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            self.compress(&block);
            input = &input[64..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..].copy_from_slice(&self.len_bits.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (idx, word) in self.state.iter().enumerate() {
            out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for idx in 0..16 {
            w[idx] = u32::from_be_bytes([
                block[idx * 4],
                block[idx * 4 + 1],
                block[idx * 4 + 2],
                block[idx * 4 + 3],
            ]);
        }
        for idx in 16..64 {
            let s0 =
                w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
            let s1 = w[idx - 2].rotate_right(17) ^ w[idx - 2].rotate_right(19) ^ (w[idx - 2] >> 10);
            w[idx] = w[idx - 16]
                .wrapping_add(s0)
                .wrapping_add(w[idx - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for idx in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[idx])
                .wrapping_add(w[idx]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct XorShim;

    impl CryptoShim for XorShim {
        fn seal(
            &self,
            key_id: u32,
            _nonce: &[u8],
            _aad: &[u8],
            plaintext: &[u8],
            ciphertext_out: &mut [u8],
            tag_out: &mut [u8],
        ) -> TelemetryResult<(usize, usize)> {
            if ciphertext_out.len() < plaintext.len() || tag_out.len() < 4 {
                return Err(TelemetryError::SizeMismatchError);
            }
            for (idx, byte) in plaintext.iter().enumerate() {
                ciphertext_out[idx] = *byte ^ (key_id as u8);
            }
            tag_out[..4].copy_from_slice(b"SEDS");
            Ok((plaintext.len(), 4))
        }

        fn open(
            &self,
            key_id: u32,
            _nonce: &[u8],
            _aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8],
            plaintext_out: &mut [u8],
        ) -> TelemetryResult<usize> {
            if plaintext_out.len() < ciphertext.len() || tag != b"SEDS" {
                return Err(TelemetryError::SizeMismatchError);
            }
            for (idx, byte) in ciphertext.iter().enumerate() {
                plaintext_out[idx] = *byte ^ (key_id as u8);
            }
            Ok(ciphertext.len())
        }
    }

    #[test]
    fn rust_crypto_shim_roundtrips_without_c_callbacks() {
        let shim = XorShim;
        let plaintext = [1_u8, 2, 3, 4];
        let mut ciphertext = [0_u8; 8];
        let mut tag = [0_u8; 8];
        let (ciphertext_len, tag_len) = seal_with(
            &shim,
            9,
            &[0; 12],
            b"aad",
            &plaintext,
            &mut ciphertext,
            &mut tag,
        )
        .unwrap();
        assert_eq!(ciphertext_len, plaintext.len());
        assert_eq!(tag_len, 4);
        let mut opened = [0_u8; 8];
        let opened_len = open_with(
            &shim,
            9,
            &[0; 12],
            b"aad",
            &ciphertext[..ciphertext_len],
            &tag[..tag_len],
            &mut opened,
        )
        .unwrap();
        assert_eq!(opened_len, plaintext.len());
        assert_eq!(&opened[..opened_len], plaintext);
    }

    #[test]
    fn managed_credentials_verify_and_reject_tamper_or_expiry() {
        let root = b"root key material with at least 32 bytes";
        let credential = ManagedCredential {
            subject_id: 0xAABB,
            key_id: 7,
            epoch: 11,
            not_before_ms: 100,
            not_after_ms: 1_000,
            permissions: 0x05,
        };
        let mut bytes = [0u8; MANAGED_CREDENTIAL_LEN];
        let len = issue_managed_credential(root, credential, &mut bytes).unwrap();
        assert_eq!(len, MANAGED_CREDENTIAL_LEN);
        assert_eq!(
            verify_managed_credential(root, &bytes, 500).unwrap(),
            credential
        );

        let mut tampered = bytes;
        tampered[20] ^= 0x01;
        assert!(verify_managed_credential(root, &tampered, 500).is_err());
        assert!(verify_managed_credential(root, &bytes, 1_001).is_err());
    }
}
