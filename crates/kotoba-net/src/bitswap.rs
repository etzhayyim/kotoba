use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
        blocks: &Vec<([u8; 36], Vec<u8>)>, s: S,
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
    ) -> Result<Vec<([u8; 36], Vec<u8>)>, D::Error> {
        struct BlockVecV;
        impl<'de> serde::de::Visitor<'de> for BlockVecV {
            type Value = Vec<([u8; 36], Vec<u8>)>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "sequence of (CID, bytes) tuples")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<([u8; 36], Vec<u8>)>, A::Error> {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitswapRequest {
    /// CIDs to check existence of (cheap, no data transfer)
    #[serde(serialize_with = "cid_serde::serialize_cid_vec", deserialize_with = "cid_serde::deserialize_cid_vec")]
    pub want_have: Vec<[u8; 36]>,
    /// CIDs to fetch bytes for
    #[serde(serialize_with = "cid_serde::serialize_cid_vec", deserialize_with = "cid_serde::deserialize_cid_vec")]
    pub want_block: Vec<[u8; 36]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitswapResponse {
    #[serde(serialize_with = "cid_serde::serialize_cid_vec", deserialize_with = "cid_serde::deserialize_cid_vec")]
    pub have: Vec<[u8; 36]>,       // CIDs this peer has
    #[serde(serialize_with = "cid_serde::serialize_cid_vec", deserialize_with = "cid_serde::deserialize_cid_vec")]
    pub dont_have: Vec<[u8; 36]>,  // CIDs this peer does not have
    #[serde(serialize_with = "cid_serde::serialize_block_vec", deserialize_with = "cid_serde::deserialize_block_vec")]
    pub blocks: Vec<([u8; 36], Vec<u8>)>, // (CID, bytes) for want_block requests
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

async fn read_cbor<T: AsyncRead + Unpin + Send, D: serde::de::DeserializeOwned>(
    io: &mut T,
) -> std::io::Result<D> {
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
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
