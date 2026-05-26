use blake3::Hasher;
use thiserror::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KotobaCid(pub [u8; 36]);

impl Default for KotobaCid {
    fn default() -> Self { Self([0u8; 36]) }
} // version(1) + codec(1) + multihash(34)

// Manual Serialize/Deserialize for [u8; 36] (fixed arrays need special handling in serde)
impl Serialize for KotobaCid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for KotobaCid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = KotobaCid;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "36-byte CID")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<KotobaCid, E> {
                if v.len() != 36 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; 36];
                arr.copy_from_slice(v);
                Ok(KotobaCid(arr))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<KotobaCid, A::Error> {
                let mut arr = [0u8; 36];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(KotobaCid(arr))
            }
        }
        d.deserialize_bytes(V)
    }
}

#[derive(Debug, Error)]
pub enum CidError {
    #[error("cbor encode error: {0}")]
    Cbor(String),
    #[error("invalid cid bytes")]
    InvalidBytes,
}

impl KotobaCid {
    pub const CODEC_DAG_CBOR: u8 = 0x71;
    pub const MH_BLAKE3: u8 = 0x1e;

    /// CIDv1 dag-cbor blake3-256 (clean room, no IPFS dep)
    pub fn from_bytes(payload: &[u8]) -> Self {
        let hash = Hasher::new().update(payload).finalize();
        let mut cid = [0u8; 36];
        cid[0] = 1;                    // CIDv1
        cid[1] = Self::CODEC_DAG_CBOR; // dag-cbor
        cid[2] = Self::MH_BLAKE3;      // blake3 multicodec
        cid[3] = 32;                   // hash length varint
        cid[4..36].copy_from_slice(hash.as_bytes());
        Self(cid)
    }

    pub fn from_cbor<T: serde::Serialize>(value: &T) -> Result<Self, CidError> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf)
            .map_err(|e| CidError::Cbor(e.to_string()))?;
        Ok(Self::from_bytes(&buf))
    }

    pub fn to_multibase(&self) -> String {
        // base32lower (multibase 'b')
        let encoded = data_encoding::BASE32_NOPAD.encode(&self.0);
        format!("b{}", encoded.to_lowercase())
    }

    /// Parse a multibase-encoded CID (base32lower, 'b' prefix).
    /// Returns `None` if the string is malformed or decodes to != 36 bytes.
    pub fn from_multibase(s: &str) -> Option<Self> {
        let hex = s.strip_prefix('b')?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(hex.to_uppercase().as_bytes())
            .ok()?;
        if bytes.len() != 36 { return None; }
        let mut arr = [0u8; 36];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }
}

impl std::fmt::Display for KotobaCid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_multibase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_header_is_cidv1_dag_cbor_blake3() {
        let cid = KotobaCid::from_bytes(b"hello");
        assert_eq!(cid.0[0], 1,                            "CIDv1 version byte");
        assert_eq!(cid.0[1], KotobaCid::CODEC_DAG_CBOR,   "dag-cbor codec");
        assert_eq!(cid.0[2], KotobaCid::MH_BLAKE3,        "blake3 multicodec");
        assert_eq!(cid.0[3], 32,                           "hash length varint");
    }

    #[test]
    fn from_bytes_is_deterministic() {
        let a = KotobaCid::from_bytes(b"kotoba");
        let b = KotobaCid::from_bytes(b"kotoba");
        assert_eq!(a, b);
    }

    #[test]
    fn from_bytes_differs_for_different_inputs() {
        let a = KotobaCid::from_bytes(b"foo");
        let b = KotobaCid::from_bytes(b"bar");
        assert_ne!(a, b);
    }

    #[test]
    fn multibase_roundtrip() {
        let cid = KotobaCid::from_bytes(b"roundtrip test");
        let encoded = cid.to_multibase();
        assert!(encoded.starts_with('b'), "multibase prefix must be 'b' (base32lower)");
        let decoded = KotobaCid::from_multibase(&encoded).expect("must roundtrip");
        assert_eq!(cid, decoded);
    }

    #[test]
    fn display_matches_to_multibase() {
        let cid = KotobaCid::from_bytes(b"display test");
        assert_eq!(format!("{cid}"), cid.to_multibase());
    }

    #[test]
    fn from_multibase_rejects_wrong_prefix() {
        let cid = KotobaCid::from_bytes(b"prefix test");
        let encoded = cid.to_multibase();
        // Replace 'b' prefix with 'z' (base58btc)
        let bad = format!("z{}", &encoded[1..]);
        assert!(KotobaCid::from_multibase(&bad).is_none());
    }

    #[test]
    fn from_multibase_rejects_truncated() {
        let cid = KotobaCid::from_bytes(b"truncated");
        let encoded = cid.to_multibase();
        // Drop last 4 chars → shorter byte sequence
        let short = &encoded[..encoded.len() - 4];
        assert!(KotobaCid::from_multibase(short).is_none());
    }

    #[test]
    fn from_cbor_is_consistent_with_from_bytes() {
        let value = "kotoba-cbor-test";
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        let expected = KotobaCid::from_bytes(&buf);
        let actual   = KotobaCid::from_cbor(&value).unwrap();
        assert_eq!(expected, actual);
    }
}
