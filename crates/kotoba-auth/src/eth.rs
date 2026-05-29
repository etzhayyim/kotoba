//! secp256k1 recovery + ETH address derivation for SIWE/EIP-191

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EthError {
    #[error("invalid signature bytes: {0}")]
    Sig(String),
    #[error("invalid DID format: {0}")]
    Did(String),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Compute EIP-191 personal_sign hash:
///   keccak256("\x19Ethereum Signed Message:\n" + len + msg)
pub fn personal_sign_hash(msg: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    Keccak256::new()
        .chain_update(prefix.as_bytes())
        .chain_update(msg)
        .finalize()
        .into()
}

/// Recover the ETH address from an EIP-191 signature.
/// `sig` is 65 bytes: r(32) + s(32) + v(1).
/// Handles both legacy v ∈ {27,28} and EIP-155 v ∈ {0,1}.
pub fn recover_eth_address(hash: &[u8; 32], sig: &[u8]) -> Result<[u8; 20], EthError> {
    if sig.len() != 65 {
        return Err(EthError::Sig(format!(
            "expected 65 bytes, got {}",
            sig.len()
        )));
    }
    let v_raw = sig[64];
    let v = if v_raw >= 27 { v_raw - 27 } else { v_raw } % 2;
    let rec_id = RecoveryId::try_from(v).map_err(|e| EthError::Sig(e.to_string()))?;
    let sig65 = Signature::from_slice(&sig[..64]).map_err(|e| EthError::Sig(e.to_string()))?;
    let vk = VerifyingKey::recover_from_prehash(hash, &sig65, rec_id)
        .map_err(|e| EthError::Sig(e.to_string()))?;

    // ETH address = keccak256(uncompressed_pubkey[1..])[12..]
    let point = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

/// Parse ETH address bytes from a DID string.
/// Accepts:
///   `did:pkh:eip155:N:0x<hex>`   — standard CAIP-74
///   `did:erc725:gftd:N:0x<hex>`  — gftd-internal
pub fn parse_eth_address_from_did(iss: &str) -> Result<[u8; 20], EthError> {
    let parts: Vec<&str> = iss.split(':').collect();
    // did:pkh:eip155:1:0x...  → parts[4]
    // did:erc725:gftd:N:0x... → parts[4]
    let hex_addr = parts
        .last()
        .ok_or_else(|| EthError::Did(iss.to_string()))?
        .trim_start_matches("0x");
    let bytes = hex::decode(hex_addr)?;
    if bytes.len() != 20 {
        return Err(EthError::Did(format!(
            "address is {} bytes, expected 20",
            bytes.len()
        )));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Convert a raw 20-byte ETH address to a gftd ERC-725 DID.
/// Format: `did:erc725:gftd:260425:0x{hex}`
pub fn eth_address_to_erc725_did(addr: &[u8; 20]) -> String {
    format!("did:erc725:gftd:260425:0x{}", hex::encode(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── eth_address_to_erc725_did ─────────────────────────────────────────────

    #[test]
    fn erc725_did_format() {
        let addr = [0x00u8; 20];
        let did = eth_address_to_erc725_did(&addr);
        assert!(did.starts_with("did:erc725:gftd:260425:0x"));
        assert_eq!(did.len(), "did:erc725:gftd:260425:0x".len() + 40);
    }

    #[test]
    fn erc725_did_known_address() {
        let mut addr = [0u8; 20];
        addr[19] = 0xAB;
        let did = eth_address_to_erc725_did(&addr);
        assert!(did.ends_with("ab"), "last byte 0xAB → hex 'ab': {did}");
    }

    // ── parse_eth_address_from_did ────────────────────────────────────────────

    #[test]
    fn parse_pkh_did() {
        let did = "did:pkh:eip155:1:0xabcdef1234567890abcdef1234567890abcdef12";
        let addr = parse_eth_address_from_did(did).unwrap();
        assert_eq!(addr[0], 0xab);
        assert_eq!(addr[19], 0x12);
    }

    #[test]
    fn parse_erc725_did() {
        let did = "did:erc725:gftd:260425:0xabcdef1234567890abcdef1234567890abcdef12";
        let addr = parse_eth_address_from_did(did).unwrap();
        assert_eq!(addr[0], 0xab);
    }

    #[test]
    fn parse_did_rejects_wrong_length() {
        // 19 bytes hex = 38 hex chars
        let did = "did:pkh:eip155:1:0xabcdef1234567890abcdef1234567890abcdef";
        let result = parse_eth_address_from_did(did);
        assert!(result.is_err());
    }

    #[test]
    fn parse_did_rejects_invalid_hex() {
        let did = "did:pkh:eip155:1:0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
        let result = parse_eth_address_from_did(did);
        assert!(result.is_err());
    }

    // ── personal_sign_hash ────────────────────────────────────────────────────

    #[test]
    fn personal_sign_hash_deterministic() {
        let h1 = personal_sign_hash(b"hello");
        let h2 = personal_sign_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn personal_sign_hash_different_messages_differ() {
        let h1 = personal_sign_hash(b"hello");
        let h2 = personal_sign_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn personal_sign_hash_is_32_bytes() {
        let h = personal_sign_hash(b"test");
        assert_eq!(h.len(), 32);
    }

    // ── recover_eth_address ───────────────────────────────────────────────────

    #[test]
    fn recover_rejects_wrong_length_sig() {
        let hash = [0u8; 32];
        let sig = [0u8; 64]; // 64 bytes, not 65
        let result = recover_eth_address(&hash, &sig);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("65"), "error should mention 65 bytes: {msg}");
    }

    // ── EthError display ──────────────────────────────────────────────────────

    #[test]
    fn eth_error_display_sig() {
        let e = EthError::Sig("bad sig".to_string());
        assert!(e.to_string().contains("bad sig"));
    }

    #[test]
    fn eth_error_display_did() {
        let e = EthError::Did("bad did".to_string());
        assert!(e.to_string().contains("bad did"));
    }

    // ── roundtrip: parse DID → encode back ───────────────────────────────────

    #[test]
    fn roundtrip_address_via_erc725_did() {
        let original = [0x11u8; 20];
        let did = eth_address_to_erc725_did(&original);
        let parsed = parse_eth_address_from_did(&did).unwrap();
        assert_eq!(original, parsed);
    }
}
