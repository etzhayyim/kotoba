"""Minimal pure-Python CBOR encoder/decoder (no C extensions).

Handles only the subset of CBOR needed by kotoba_langgraph:
  - encode: dict (str keys), str, bytes, int, float, list, None, bool
  - decode: same

This exists because cbor2 5.x imports from `._cbor2` (Rust/C extension) at
module load and has no pure-Python fallback, which breaks componentize-py.

CBOR major types:
  0 = unsigned int, 1 = negative int, 2 = bytes, 3 = text, 4 = array,
  5 = map, 6 = tag (not used), 7 = float/simple
"""

from __future__ import annotations

import struct
from typing import Any


# ── Encoder ──────────────────────────────────────────────────────────────────

def _encode_head(major: int, value: int) -> bytes:
    major <<= 5
    if value <= 23:
        return bytes([major | value])
    if value <= 0xFF:
        return bytes([major | 24, value])
    if value <= 0xFFFF:
        return bytes([major | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([major | 26]) + struct.pack(">I", value)
    return bytes([major | 27]) + struct.pack(">Q", value)


def dumps(obj: Any) -> bytes:
    if obj is None:
        return b"\xf6"
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if isinstance(obj, bool):  # must be before int
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        if obj >= 0:
            return _encode_head(0, obj)
        return _encode_head(1, -obj - 1)
    if isinstance(obj, float):
        return b"\xfb" + struct.pack(">d", obj)
    if isinstance(obj, (bytes, bytearray)):
        return _encode_head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        enc = obj.encode("utf-8")
        return _encode_head(3, len(enc)) + enc
    if isinstance(obj, (list, tuple)):
        out = _encode_head(4, len(obj))
        for item in obj:
            out += dumps(item)
        return out
    if isinstance(obj, dict):
        out = _encode_head(5, len(obj))
        for k, v in obj.items():
            out += dumps(k)
            out += dumps(v)
        return out
    raise TypeError(f"kotoba_langgraph._cbor: unsupported type {type(obj)}")


# ── Decoder ──────────────────────────────────────────────────────────────────

def _decode_one(data: bytes, pos: int) -> tuple[Any, int]:
    b = data[pos]
    major = b >> 5
    info = b & 0x1F
    pos += 1

    if info <= 23:
        length = info
    elif info == 24:
        length = data[pos]; pos += 1
    elif info == 25:
        length = struct.unpack_from(">H", data, pos)[0]; pos += 2
    elif info == 26:
        length = struct.unpack_from(">I", data, pos)[0]; pos += 4
    elif info == 27:
        length = struct.unpack_from(">Q", data, pos)[0]; pos += 8
    elif info == 31:
        length = -1  # indefinite length (not used by ciborium in our case)
    else:
        length = info

    if major == 0:
        return length, pos
    if major == 1:
        return -length - 1, pos
    if major == 2:
        end = pos + length
        return bytes(data[pos:end]), end
    if major == 3:
        end = pos + length
        return data[pos:end].decode("utf-8"), end
    if major == 4:
        items = []
        for _ in range(length):
            item, pos = _decode_one(data, pos)
            items.append(item)
        return items, pos
    if major == 5:
        d = {}
        for _ in range(length):
            k, pos = _decode_one(data, pos)
            v, pos = _decode_one(data, pos)
            d[k] = v
        return d, pos
    if major == 7:
        if info == 20: return False, pos
        if info == 21: return True, pos
        if info == 22: return None, pos
        if info == 25:  # float16 (half)
            raw = struct.unpack_from(">H", data, pos - 2)[0]
            # simple half-float decode
            exp = (raw >> 10) & 0x1F
            mant = raw & 0x3FF
            sign = -1 if raw >> 15 else 1
            if exp == 0:
                val = sign * (mant / 1024.0) * (2 ** -14)
            elif exp == 31:
                val = sign * (float("inf") if mant == 0 else float("nan"))
            else:
                val = sign * (1 + mant / 1024.0) * (2 ** (exp - 15))
            return val, pos
        if info == 26:
            return struct.unpack_from(">f", data, pos - 4)[0], pos
        if info == 27:
            return struct.unpack_from(">d", data, pos - 8)[0], pos
    raise ValueError(f"kotoba_langgraph._cbor: unsupported major={major} info={info}")


def loads(data: bytes) -> Any:
    obj, _ = _decode_one(data, 0)
    return obj
