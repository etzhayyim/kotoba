use hkdf::Hkdf;
use sha2::Sha256;

pub const HKDF_KEY_LEN: usize = 32;

/// HKDF-SHA256 extract-then-expand.
/// `ikm` = input key material, `info` = context label.
/// Returns 32 bytes of key material.
pub fn derive_key(ikm: &[u8], info: &[u8]) -> [u8; HKDF_KEY_LEN] {
    derive_key_with_salt(ikm, &[], info)
}

/// HKDF-SHA256 with explicit salt.
pub fn derive_key_with_salt(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; HKDF_KEY_LEN] {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; HKDF_KEY_LEN];
    hk.expand(info, &mut okm).expect("HKDF expand: output len <= 255*HashLen");
    okm
}

/// HKDF-SHA256 returning arbitrary-length output.
pub fn derive_bytes(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("HKDF expand: output len <= 255*HashLen");
    okm
}

/// Double-HKDF ratchet step: (root_key, chain_key) = KDF(root_key, dh_output).
/// Returns (new_root_key, new_chain_key).
pub fn ratchet_root(root_key: &[u8; 32], dh_out: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    let salt = Some(root_key.as_ref());
    let hk = Hkdf::<Sha256>::new(salt, dh_out);
    hk.expand(b"kotoba-ratchet-root", &mut out).expect("HKDF expand: 64 bytes is within 255*HashLen limit");
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    (rk, ck)
}

/// Symmetric chain ratchet: (chain_key, message_key) = KDF(chain_key).
pub fn ratchet_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mk_mac = HmacSha256::new_from_slice(chain_key).expect("HMAC-SHA256 accepts any key length");
    mk_mac.update(&[0x01]);
    let mk: [u8; 32] = mk_mac.finalize().into_bytes().into();

    let mut ck_mac = HmacSha256::new_from_slice(chain_key).expect("HMAC-SHA256 accepts any key length");
    ck_mac.update(&[0x02]);
    let ck: [u8; 32] = ck_mac.finalize().into_bytes().into();

    (ck, mk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() {
        let k1 = derive_key(b"secret", b"info");
        let k2 = derive_key(b"secret", b"info");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_different_info_different_output() {
        let k1 = derive_key(b"secret", b"info-a");
        let k2 = derive_key(b"secret", b"info-b");
        assert_ne!(k1, k2);
    }

    #[test]
    fn ratchet_chain_produces_distinct_mk_ck() {
        let ck = [0xABu8; 32];
        let (new_ck, mk) = ratchet_chain(&ck);
        assert_ne!(new_ck, mk);
        assert_ne!(new_ck, ck);
    }
}
