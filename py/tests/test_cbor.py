"""Tests for kotoba_langgraph._cbor — pure-Python CBOR roundtrip."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from kotoba_langgraph._cbor import dumps, loads


def rt(obj):
    """Round-trip helper."""
    return loads(dumps(obj))


class TestPrimitives:
    def test_none(self):
        assert rt(None) is None

    def test_true(self):
        assert rt(True) is True

    def test_false(self):
        assert rt(False) is False

    def test_zero(self):
        assert rt(0) == 0

    def test_positive_int_small(self):
        assert rt(23) == 23

    def test_positive_int_1byte(self):
        assert rt(255) == 255

    def test_positive_int_2byte(self):
        assert rt(1000) == 1000

    def test_positive_int_4byte(self):
        assert rt(100000) == 100000

    def test_positive_int_8byte(self):
        assert rt(2**32 + 1) == 2**32 + 1

    def test_negative_int(self):
        assert rt(-1) == -1
        assert rt(-100) == -100

    def test_float(self):
        assert rt(3.14) == pytest.approx(3.14)

    def test_empty_str(self):
        assert rt("") == ""

    def test_ascii_str(self):
        assert rt("hello") == "hello"

    def test_unicode_str(self):
        assert rt("こんにちは") == "こんにちは"

    def test_bytes(self):
        assert rt(b"\x00\x01\x02") == b"\x00\x01\x02"

    def test_empty_bytes(self):
        assert rt(b"") == b""


class TestCollections:
    def test_empty_list(self):
        assert rt([]) == []

    def test_list_of_ints(self):
        assert rt([1, 2, 3]) == [1, 2, 3]

    def test_nested_list(self):
        assert rt([[1, 2], [3, 4]]) == [[1, 2], [3, 4]]

    def test_empty_dict(self):
        assert rt({}) == {}

    def test_dict_str_keys(self):
        d = {"a": 1, "b": "two", "c": None}
        assert rt(d) == d

    def test_nested_dict(self):
        d = {"outer": {"inner": 42}}
        assert rt(d) == d

    def test_mixed(self):
        obj = {"items": [1, "two", None, True, False], "count": 5}
        assert rt(obj) == obj


class TestQuadObjectText:
    """QuadObject::Text ciborium encoding — the critical format for KQE."""

    def test_text_wrapper(self):
        payload = {"Text": "hello world"}
        encoded = dumps(payload)
        decoded = loads(encoded)
        assert decoded == {"Text": "hello world"}

    def test_text_json_string(self):
        import json
        state = {"messages": [{"role": "user", "content": "hi"}], "count": 1}
        json_str = json.dumps(state)
        payload = {"Text": json_str}
        assert loads(dumps(payload)) == {"Text": json_str}

    def test_cbor_head_bytes(self):
        # {"Text": "hi"} → CBOR map(1) + key "Text" + val "hi"
        encoded = dumps({"Text": "hi"})
        # First byte: major 5 (map) | 1 item → 0xA1
        assert encoded[0] == 0xA1


class TestUnsupportedType:
    def test_set_raises(self):
        with pytest.raises(TypeError):
            dumps({1, 2, 3})

    def test_object_raises(self):
        with pytest.raises(TypeError):
            dumps(object())
