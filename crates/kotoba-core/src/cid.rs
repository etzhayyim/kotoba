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
