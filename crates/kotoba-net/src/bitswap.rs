use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

type CidBytes = [u8; 36];
type BlockEntry = (CidBytes, Vec<u8>);
#[allow(unused_imports)]
use serde::ser::SerializeSeq as _;

pub const BITSWAP_PROTOCOL: &str = "/kotoba/bitswap/1.0.0";

// ---------------------------------------------------------------------------
// Serde helpers for Vec<[u8; 36]>
// Serde only derives Serialize/Deserialize for [T; N] up to N=32,
// so we provide explicit impls for 36-byte CID arrays.
// ---------------------------------------------------------------------------

mod cid_serde {
    use super::*;

    pub fn serialize_cid_arr<S: Serializer>(cid: &[u8; 36], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(cid)
    }

    pub fn deserialize_cid_arr<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 36], D::Error> {
        let buf = serde_bytes::ByteBuf::deserialize(d)?;
        let v: &[u8] = buf.as_ref();
        v.try_into().map_err(|_| serde::de::Error::invalid_length(v.len(), &"36-byte CID"))
    }

    pub fn serialize_cid_vec<S: Serializer>(cids: &Vec<[u8; 36]>, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(cids.len()))?;
        for cid in cids {
            seq.serialize_element(&serde_bytes::Bytes::new(cid))?;
        }
        seq.end()
    }

    pub fn deserialize_cid_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 36]>, D::Error> {
        struct VecV;
        impl<'de> serde::de::Visitor<'de> for VecV {
            type Value = Vec<[u8; 36]>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "sequence of 36-byte CIDs")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<[u8; 36]>, A::Error> {
                let mut out = Vec::new();
                while let Some(bytes) = seq.next_element::<serde_bytes::ByteBuf>()? {
                    let v: &[u8] = bytes.as_ref();
                    let arr: [u8; 36] = v.try_into().map_err(|_| {
                        serde::de::Error::invalid_length(v.len(), &self)
                    })?;
                    out.push(arr);
                }
                Ok(out)
            }
        }
        d.deserialize_seq(VecV)
    }

    pub fn serialize_block_vec<S: Serializer>(
        blocks: &Vec<BlockEntry>, s: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(blocks.len()))?;
        for (cid, data) in blocks {
            seq.serialize_element(&(serde_bytes::Bytes::new(cid), serde_bytes::Bytes::new(data)))?;
        }
        seq.end()
    }

    pub fn deserialize_block_vec<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<BlockEntry>, D::Error> {
        struct BlockVecV;
        impl<'de> serde::de::Visitor<'de> for BlockVecV {
            type Value = Vec<BlockEntry>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "sequence of (CID, bytes) tuples")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<BlockEntry>, A::Error> {
                let mut out = Vec::new();
                while let Some((cid_buf, data_buf)) =
                    seq.next_element::<(serde_bytes::ByteBuf, serde_bytes::ByteBuf)>()?
                {
                    let cid_bytes: &[u8] = cid_buf.as_ref();
                    let arr: [u8; 36] = cid_bytes.try_into().map_err(|_| {
                        serde::de::Error::invalid_length(cid_bytes.len(), &Self)
                    })?;
                    out.push((arr, data_buf.into_vec()));
                }
                Ok(out)
            }
        }
        d.deserialize_seq(BlockVecV)
    }

    pub fn serialize_opt_cid<S: Serializer>(
        opt: &Option<[u8; 36]>, s: S,
    ) -> Result<S::Ok, S::Error> {
        match opt {
            Some(cid) => s.serialize_some(&serde_bytes::Bytes::new(cid)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize_opt_cid<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<[u8; 36]>, D::Error> {
        struct OptCidV;
        impl<'de> serde::de::Visitor<'de> for OptCidV {
            type Value = Option<[u8; 36]>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "optional 36-byte CID")
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                let buf = serde_bytes::ByteBuf::deserialize(d)?;
                let v: &[u8] = buf.as_ref();
                v.try_into()
                    .map(Some)
                    .map_err(|_| serde::de::Error::invalid_length(v.len(), &self))
            }
        }
        d.deserialize_option(OptCidV)
    }

    pub fn serialize_want_since_vec<S: Serializer>(
        items: &Vec<WantSince>, s: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(items.len()))?;
        for ws in items {
            seq.serialize_element(ws)?;
        }
        seq.end()
    }

    pub fn deserialize_want_since_vec<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<WantSince>, D::Error> {
        Vec::<WantSince>::deserialize(d)
    }
}

/// Selective-sync delta request: give me all commits in `graph_cid` since `head_cid`.
/// `head_cid = None` means fresh agent — return full history from the graph root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WantSince {
    #[serde(serialize_with = "cid_serde::serialize_cid_arr", deserialize_with = "cid_serde::deserialize_cid_arr")]
    pub graph_cid: [u8; 36],
    pub since_seq: u64,
    #[serde(
        serialize_with = "cid_serde::serialize_opt_cid",
        deserialize_with = "cid_serde::deserialize_opt_cid"
    )]
    pub head_cid: Option<[u8; 36]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitswapRequest {
    /// CIDs to check existence of (cheap, no data transfer)
    #[serde(serialize_with = "cid_serde::serialize_cid_vec", deserialize_with = "cid_serde::deserialize_cid_vec")]
    pub want_have: Vec<[u8; 36]>,
    /// CIDs to fetch bytes for
    #[serde(serialize_with = "cid_serde::serialize_cid_vec", deserialize_with = "cid_serde::deserialize_cid_vec")]
    pub want_block: Vec<[u8; 36]>,
    /// Selective-sync delta requests (SyncWindow wire format)
    #[serde(
        default,
        serialize_with = "cid_serde::serialize_want_since_vec",
        deserialize_with = "cid_serde::deserialize_want_since_vec"
    )]
    pub want_since: Vec<WantSince>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitswapResponse {
    #[serde(serialize_with = "cid_serde::serialize_cid_vec", deserialize_with = "cid_serde::deserialize_cid_vec")]
    pub have: Vec<[u8; 36]>,       // CIDs this peer has
    #[serde(serialize_with = "cid_serde::serialize_cid_vec", deserialize_with = "cid_serde::deserialize_cid_vec")]
    pub dont_have: Vec<[u8; 36]>,  // CIDs this peer does not have
    #[serde(serialize_with = "cid_serde::serialize_block_vec", deserialize_with = "cid_serde::deserialize_block_vec")]
    pub blocks: Vec<BlockEntry>, // (CID, bytes) for want_block requests
    /// CBOR-serialised Commit structs, oldest-first, for want_since delta responses
    #[serde(
        default,
        serialize_with = "cid_serde::serialize_block_vec",
        deserialize_with = "cid_serde::deserialize_block_vec"
    )]
    pub delta_commits: Vec<BlockEntry>,
}

#[derive(Clone, Default)]
pub struct BitswapCodec;

#[async_trait]
impl request_response::Codec for BitswapCodec {
    type Protocol = &'static str;
    type Request  = BitswapRequest;
    type Response = BitswapResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_cbor(io).await
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_cbor(io).await
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_cbor(io, &req).await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, resp: Self::Response) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_cbor(io, &resp).await
    }
}

/// Maximum bitswap message size (32 MiB). A peer advertising a larger payload
/// is either faulty or malicious — reject immediately to prevent OOM allocation.
const MAX_BITSWAP_MSG_BYTES: usize = 32 * 1024 * 1024;

async fn read_cbor<T: AsyncRead + Unpin + Send, D: serde::de::DeserializeOwned>(
    io: &mut T,
) -> std::io::Result<D> {
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_BITSWAP_MSG_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bitswap message too large ({len} bytes, limit {MAX_BITSWAP_MSG_BYTES})"),
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    ciborium::from_reader(&buf[..])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

async fn write_cbor<T: AsyncWrite + Unpin + Send, S: Serialize>(
    io: &mut T, value: &S,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    io.write_all(&(buf.len() as u32).to_be_bytes()).await?;
    io.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_cbor_rejects_oversized_length_prefix() {
        // Simulate a peer sending 0xFFFFFFFF (4 GiB) as the 4-byte length prefix.
        // Without the size guard this would cause an immediate OOM allocation.
        let oversized_len: u32 = u32::MAX;
        let fake_stream: &[u8] = &oversized_len.to_be_bytes();

        let result: std::io::Result<BitswapRequest> = read_cbor(&mut &*fake_stream).await;
        assert!(result.is_err(), "oversized length prefix must be rejected");
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too large"), "error should mention size: {err}");
    }

    #[tokio::test]
    async fn read_cbor_accepts_valid_size() {
        // A small valid CBOR-encoded BitswapRequest should pass through cleanly.
        let req = BitswapRequest {
            want_have:  vec![],
            want_block: vec![],
            want_since: vec![],
        };
        let mut encoded: Vec<u8> = Vec::new();
        ciborium::into_writer(&req, &mut encoded).unwrap();
        let len_prefix = (encoded.len() as u32).to_be_bytes();
        let stream: Vec<u8> = [&len_prefix[..], &encoded].concat();

        let result: std::io::Result<BitswapRequest> = read_cbor(&mut &*stream.as_slice()).await;
        assert!(result.is_ok(), "valid small request must be accepted: {result:?}");
    }
}
