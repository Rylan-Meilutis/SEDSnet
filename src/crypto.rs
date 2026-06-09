//! Feature-gated cryptography shim interfaces.
//!
//! This module intentionally does not provide a software cipher. It defines the
//! contract used by embedded applications to plug in board-specific hardware
//! acceleration, secure-element drivers, or an application-owned Rust crypto
//! implementation.

use crate::{TelemetryError, TelemetryResult};

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
}
