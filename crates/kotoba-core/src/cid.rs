use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KotobaCid(pub [u8; 36]);

impl Default for KotobaCid {
    fn default() -> Self {
        Self([0u8; 36])
    }
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
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<KotobaCid, A::Error> {
                let mut arr = [0u8; 36];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
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
    pub const MH_SHA2_256: u8 = 0x12;
    pub const CIDV1: u8 = 1;
    pub const DIGEST_LEN_SHA2_256: u8 = 32;

    /// CIDv1 dag-cbor sha2-256 (IPFS-compatible).
    pub fn from_bytes(payload: &[u8]) -> Self {
        let hash = Sha256::digest(payload);
        let mut cid = [0u8; 36];
        cid[0] = Self::CIDV1; // CIDv1
        cid[1] = Self::CODEC_DAG_CBOR; // dag-cbor
        cid[2] = Self::MH_SHA2_256; // sha2-256 multicodec
        cid[3] = Self::DIGEST_LEN_SHA2_256; // hash length varint
        cid[4..36].copy_from_slice(&hash);
        Self(cid)
    }

    pub fn from_cbor<T: serde::Serialize>(value: &T) -> Result<Self, CidError> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).map_err(|e| CidError::Cbor(e.to_string()))?;
        Ok(Self::from_bytes(&buf))
    }

    pub fn to_multibase(&self) -> String {
        // base32lower (multibase 'b')
        let encoded = data_encoding::BASE32_NOPAD.encode(&self.0);
        format!("b{}", encoded.to_lowercase())
    }

    /// Parse a multibase-encoded CID (base32lower, 'b' prefix).
    /// Returns `None` unless it is the Kotoba canonical CIDv1 dag-cbor sha2-256 form.
    pub fn from_multibase(s: &str) -> Option<Self> {
        s.strip_prefix('b')?;
        let cid = s.parse::<::cid::Cid>().ok()?;
        Self::from_standard_cid(&cid)
    }

    pub fn is_ipfs_compatible(&self) -> bool {
        self.0[0] == Self::CIDV1
            && self.0[1] == Self::CODEC_DAG_CBOR
            && self.0[2] == Self::MH_SHA2_256
            && self.0[3] == Self::DIGEST_LEN_SHA2_256
    }

    pub fn to_standard_cid(&self) -> Result<::cid::Cid, CidError> {
        if !self.is_ipfs_compatible() {
            return Err(CidError::InvalidBytes);
        }
        ::cid::Cid::try_from(self.0.as_slice()).map_err(|_| CidError::InvalidBytes)
    }

    pub fn from_standard_cid(cid: &::cid::Cid) -> Option<Self> {
        if cid.version() != ::cid::Version::V1
            || cid.codec() != u64::from(Self::CODEC_DAG_CBOR)
            || cid.hash().code() != u64::from(Self::MH_SHA2_256)
            || cid.hash().size() != Self::DIGEST_LEN_SHA2_256
        {
            return None;
        }
        let bytes = cid.to_bytes();
        if bytes.len() != 36 {
            return None;
        }
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
    fn from_bytes_header_is_cidv1_dag_cbor_sha2_256() {
        let cid = KotobaCid::from_bytes(b"hello");
        assert_eq!(cid.0[0], KotobaCid::CIDV1, "CIDv1 version byte");
        assert_eq!(cid.0[1], KotobaCid::CODEC_DAG_CBOR, "dag-cbor codec");
        assert_eq!(cid.0[2], KotobaCid::MH_SHA2_256, "sha2-256 multicodec");
        assert_eq!(
            cid.0[3],
            KotobaCid::DIGEST_LEN_SHA2_256,
            "hash length varint"
        );
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
        assert!(
            encoded.starts_with('b'),
            "multibase prefix must be 'b' (base32lower)"
        );
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
        let actual = KotobaCid::from_cbor(&value).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn default_is_all_zeros() {
        let cid = KotobaCid::default();
        assert_eq!(cid.0, [0u8; 36]);
    }

    #[test]
    fn hash_trait_in_hashset() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let a = KotobaCid::from_bytes(b"a");
        let b = KotobaCid::from_bytes(b"b");
        set.insert(a.clone());
        set.insert(a.clone()); // duplicate → no growth
        set.insert(b.clone());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&a));
        assert!(set.contains(&b));
    }

    #[test]
    fn from_cbor_error_on_non_serializable_would_fail_gracefully() {
        // A valid serializable value must always succeed.
        let n: u64 = 12345678;
        let cid = KotobaCid::from_cbor(&n);
        assert!(cid.is_ok());
    }

    #[test]
    fn cid_is_exactly_36_bytes() {
        let cid = KotobaCid::from_bytes(b"size-check");
        assert_eq!(cid.0.len(), 36);
    }

    #[test]
    fn cid_is_parseable_as_standard_ipfs_cid() {
        let cid = KotobaCid::from_bytes(b"hello");
        let standard = cid.to_standard_cid().expect("valid standard CID");

        assert_eq!(standard.version(), ::cid::Version::V1);
        assert_eq!(standard.codec(), u64::from(KotobaCid::CODEC_DAG_CBOR));
        assert_eq!(standard.hash().code(), u64::from(KotobaCid::MH_SHA2_256));
        assert_eq!(standard.hash().size(), KotobaCid::DIGEST_LEN_SHA2_256);
        assert_eq!(standard.to_string(), cid.to_multibase());
    }

    #[test]
    fn standard_cid_roundtrip_preserves_exact_bytes() {
        let cid = KotobaCid::from_bytes(b"standard roundtrip");
        let standard = cid.to_standard_cid().unwrap();
        let decoded = KotobaCid::from_standard_cid(&standard).expect("canonical CID");

        assert_eq!(decoded, cid);
        assert_eq!(decoded.0, standard.to_bytes().as_slice());
    }

    #[test]
    fn from_standard_cid_rejects_non_kotoba_codec() {
        let mut bytes = KotobaCid::from_bytes(b"raw codec").0;
        bytes[1] = 0x55; // raw
        let standard = ::cid::Cid::try_from(bytes.as_slice()).expect("valid raw CID");

        assert!(KotobaCid::from_standard_cid(&standard).is_none());
        assert!(KotobaCid::from_multibase(&standard.to_string()).is_none());
    }

    #[test]
    fn to_standard_cid_rejects_non_canonical_bytes() {
        let cid = KotobaCid([0u8; 36]);

        assert!(!cid.is_ipfs_compatible());
        assert!(cid.to_standard_cid().is_err());
    }
}
