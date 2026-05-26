use bytes::{Bytes, BytesMut, BufMut};

/// KAIS — Kotoba Instruction Set
/// 8-bit header: [7:4]=TYPE [3]=CMP [2]=FRG [1]=ACK [0]=PRI
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Call        = 0x0, // CALL: sub-program invoke
    Read        = 0x1, // READ: Arrangement slice
    Recv        = 0x2, // RECV: inbox drain (Phase 1)
    Write       = 0x3, // WRITE: Delta(+1) emit
    Halt        = 0x4, // HALT: Vote to Halt + checkpoint
    Derive      = 0x5, // DERIVE: Prolly diff CID
    ShelfGet    = 0x6, // SHELF_GET: KV read
    Probe       = 0x7, // PROBE: bloom filter READ
    Verify      = 0x8, // VERIFY: CACAO chain
    Load        = 0x9, // LOAD: bulk Arrangement
    Ack         = 0xA, // ACK: RECV complete
    Nop         = 0xB, // NOP: keepalive ping
    NopR        = 0xC, // NOP: keepalive pong
    Retract     = 0xD, // RETRACT: Delta(-1) emit
    Fault       = 0xE, // FAULT: error HALT
    CallForeign = 0xF, // CALL_FOREIGN: LLM/external
}

impl FrameType {
    pub fn from_nibble(n: u8) -> Option<Self> {
        match n {
            0x0 => Some(Self::Call),
            0x1 => Some(Self::Read),
            0x2 => Some(Self::Recv),
            0x3 => Some(Self::Write),
            0x4 => Some(Self::Halt),
            0x5 => Some(Self::Derive),
            0x6 => Some(Self::ShelfGet),
            0x7 => Some(Self::Probe),
            0x8 => Some(Self::Verify),
            0x9 => Some(Self::Load),
            0xA => Some(Self::Ack),
            0xB => Some(Self::Nop),
            0xC => Some(Self::NopR),
            0xD => Some(Self::Retract),
            0xE => Some(Self::Fault),
            0xF => Some(Self::CallForeign),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FrameFlags {
    pub compressed: bool, // bit 3
    pub fragment:   bool, // bit 2
    pub ack_req:    bool, // bit 1
    pub priority:   bool, // bit 0
}

impl FrameFlags {
    pub fn to_nibble(&self) -> u8 {
        (self.compressed as u8) << 3
            | (self.fragment as u8) << 2
            | (self.ack_req as u8) << 1
            | (self.priority as u8)
    }
    pub fn from_nibble(n: u8) -> Self {
        Self {
            compressed: (n >> 3) & 1 == 1,
            fragment:   (n >> 2) & 1 == 1,
            ack_req:    (n >> 1) & 1 == 1,
            priority:   n & 1 == 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags:      FrameFlags,
    pub payload:    Bytes,
}

impl Frame {
    pub fn encode(&self) -> Bytes {
        let header = ((self.frame_type as u8) << 4) | self.flags.to_nibble();
        let len = self.payload.len();
        let mut buf = BytesMut::with_capacity(1 + varint_len(len) + len);
        buf.put_u8(header);
        put_varint(&mut buf, len as u64);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(src: &[u8]) -> Option<(Self, usize)> {
        if src.is_empty() { return None; }
        let header = src[0];
        let frame_type = FrameType::from_nibble(header >> 4)?;
        let flags = FrameFlags::from_nibble(header & 0x0F);
        let (len, varint_bytes) = read_varint(&src[1..])?;
        let offset = 1 + varint_bytes;
        let end = offset + len as usize;
        if src.len() < end { return None; }
        let payload = Bytes::copy_from_slice(&src[offset..end]);
        Some((Self { frame_type, flags, payload }, end))
    }
}

fn varint_len(n: usize) -> usize {
    let mut n = n;
    let mut len = 1;
    while n >= 0x80 { n >>= 7; len += 1; }
    len
}

fn put_varint(buf: &mut BytesMut, mut n: u64) {
    loop {
        let byte = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 { buf.put_u8(byte); break; }
        buf.put_u8(byte | 0x80);
    }
}

fn read_varint(src: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;
    for (i, &byte) in src.iter().enumerate() {
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 { return Some((result, i + 1)); }
        shift += 7;
        if shift >= 64 { return None; }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(ft: FrameType, flags: FrameFlags, payload: &[u8]) {
        let frame = Frame { frame_type: ft, flags, payload: Bytes::copy_from_slice(payload) };
        let encoded = frame.encode();
        let (decoded, consumed) = Frame::decode(&encoded).expect("must decode");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.frame_type, frame.frame_type);
        assert_eq!(decoded.payload, frame.payload);
    }

    #[test]
    fn encode_decode_call_empty_payload() {
        round_trip(FrameType::Call, FrameFlags::default(), b"");
    }

    #[test]
    fn encode_decode_write_with_payload() {
        round_trip(FrameType::Write, FrameFlags::default(), b"hello-world");
    }

    #[test]
    fn encode_decode_call_foreign_with_flags() {
        let flags = FrameFlags { compressed: true, fragment: false, ack_req: true, priority: false };
        round_trip(FrameType::CallForeign, flags, b"llm-payload");
    }

    #[test]
    fn all_frame_types_roundtrip() {
        let types = [
            FrameType::Call, FrameType::Read, FrameType::Recv, FrameType::Write,
            FrameType::Halt, FrameType::Derive, FrameType::ShelfGet, FrameType::Probe,
            FrameType::Verify, FrameType::Load, FrameType::Ack, FrameType::Nop,
            FrameType::NopR, FrameType::Retract, FrameType::Fault, FrameType::CallForeign,
        ];
        for ft in types {
            round_trip(ft, FrameFlags::default(), b"test");
        }
    }

    #[test]
    fn decode_returns_none_on_empty() {
        assert!(Frame::decode(b"").is_none());
    }

    #[test]
    fn decode_returns_none_on_truncated_payload() {
        let frame = Frame {
            frame_type: FrameType::Read,
            flags: FrameFlags::default(),
            payload: Bytes::from_static(b"full-payload"),
        };
        let encoded = frame.encode();
        // Drop last byte to simulate truncation
        assert!(Frame::decode(&encoded[..encoded.len() - 1]).is_none());
    }

    #[test]
    fn flags_nibble_roundtrip() {
        for bits in 0u8..16 {
            let flags = FrameFlags::from_nibble(bits);
            assert_eq!(flags.to_nibble(), bits);
        }
    }

    #[test]
    fn frame_type_from_nibble_roundtrip() {
        for n in 0u8..16 {
            let ft = FrameType::from_nibble(n).expect("all nibbles 0-15 are valid FrameType");
            assert_eq!(ft as u8, n);
        }
    }

    #[test]
    fn large_payload_varint_encoding() {
        // Payload large enough to require multi-byte varint (>= 128 bytes)
        let payload = vec![0xABu8; 200];
        round_trip(FrameType::Load, FrameFlags::default(), &payload);
    }
}
