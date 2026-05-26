use thiserror::Error;

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];

#[derive(Debug, Error)]
pub enum DidKeyError {
    #[error("not a did:key DID: {0}")]
    NotDidKey(String),
    #[error("multibase decode error: {0}")]
    MultibaseDecode(String),
    #[error("missing Ed25519 multicodec prefix [0xed, 0x01]")]
    MissingCodecPrefix,
    #[error("invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
}

/// Extract the raw 32-byte Ed25519 public key from a `did:key:z6Mk...` DID.
pub fn parse_ed25519_did_key(did: &str) -> Result<[u8; 32], DidKeyError> {
    let key_str = did
        .strip_prefix("did:key:")
        .ok_or_else(|| DidKeyError::NotDidKey(did.to_string()))?;

    let (_, bytes) = multibase::decode(key_str)
        .map_err(|e| DidKeyError::MultibaseDecode(e.to_string()))?;

    if bytes.len() < 2 || bytes[0] != ED25519_CODEC[0] || bytes[1] != ED25519_CODEC[1] {
        return Err(DidKeyError::MissingCodecPrefix);
    }

    let key_bytes = &bytes[2..];
    let len = key_bytes.len();
    if len != 32 {
        return Err(DidKeyError::InvalidKeyLength(len));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(key_bytes);
    Ok(arr)
}

/// Build a `did:key:z6Mk...` DID from a raw 32-byte Ed25519 public key.
pub fn ed25519_pubkey_to_did_key(pubkey: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.extend_from_slice(&ED25519_CODEC);
    payload.extend_from_slice(pubkey);
    let encoded = multibase::encode(multibase::Base::Base58Btc, &payload);
    format!("did:key:{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_keypair() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn roundtrip_pubkey_to_did_key_and_back() {
        let sk = test_keypair();
        let pk = sk.verifying_key();
        let did = ed25519_pubkey_to_did_key(pk.as_bytes());
        assert!(did.starts_with("did:key:z6Mk"), "DID should start with did:key:z6Mk, got: {did}");
        let recovered = parse_ed25519_did_key(&did).unwrap();
        assert_eq!(&recovered, pk.as_bytes());
    }

    #[test]
    fn parse_non_did_key_errors() {
        assert!(parse_ed25519_did_key("did:pkh:eip155:1:0xabc").is_err());
    }

    #[test]
    fn parse_wrong_codec_errors() {
        // Build a payload with secp256k1 codec [0xe7, 0x01] instead of ed25519
        let mut payload = vec![0xe7u8, 0x01];
        payload.extend_from_slice(&[0u8; 32]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &payload);
        let did = format!("did:key:{encoded}");
        let err = parse_ed25519_did_key(&did).unwrap_err();
        assert!(matches!(err, DidKeyError::MissingCodecPrefix));
    }

    #[test]
    fn parse_invalid_key_length_errors() {
        // Build a payload with correct ed25519 codec but wrong key length (16 bytes instead of 32)
        let mut payload = vec![0xedu8, 0x01];
        payload.extend_from_slice(&[0u8; 16]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &payload);
        let did = format!("did:key:{encoded}");
        let err = parse_ed25519_did_key(&did).unwrap_err();
        assert!(matches!(err, DidKeyError::InvalidKeyLength(16)));
    }

    #[test]
    fn roundtrip_is_inverse() {
        // pubkey → DID → pubkey should be lossless
        let pubkey = [0xABu8; 32];
        let did = ed25519_pubkey_to_did_key(&pubkey);
        let recovered = parse_ed25519_did_key(&did).unwrap();
        assert_eq!(recovered, pubkey);
    }

    #[test]
    fn error_display_messages() {
        let e1 = DidKeyError::NotDidKey("did:pkh:foo".to_string());
        assert!(e1.to_string().contains("not a did:key"));

        let e2 = DidKeyError::MissingCodecPrefix;
        assert!(e2.to_string().contains("Ed25519"));

        let e3 = DidKeyError::InvalidKeyLength(16);
        assert!(e3.to_string().contains("16"));

        let e4 = DidKeyError::MultibaseDecode("bad base".to_string());
        assert!(e4.to_string().contains("bad base"));
    }

    #[test]
    fn did_key_starts_with_z6mk() {
        let sk = test_keypair();
        let pk = sk.verifying_key();
        let did = ed25519_pubkey_to_did_key(pk.as_bytes());
        // z6Mk is the multibase base58btc prefix for ed25519 keys
        assert!(did.starts_with("did:key:z6Mk"), "expected did:key:z6Mk prefix, got: {did}");
    }
}
