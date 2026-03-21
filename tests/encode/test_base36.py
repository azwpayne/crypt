"""Tests for Base36 encoding."""

from crypt.encode.base36 import decode_base36, encode_base36


class TestBase36:
  def test_encode_simple(self):
    # 255 in base36 should be "73"
    encoded = encode_base36(b"\xff")
    assert encoded == "73"

  def test_roundtrip(self):
    data = b"Hello, World!"
    assert decode_base36(encode_base36(data)) == data

  def test_roundtrip_binary(self):
    data = bytes(range(16))
    assert decode_base36(encode_base36(data)) == data

  def test_lowercase_output(self):
    encoded = encode_base36(b"test")
    assert encoded == encoded.lower()

  def test_decode_case_insensitive(self):
    data = b"abc"
    enc = encode_base36(data)
    assert decode_base36(enc.upper()) == decode_base36(enc.lower())

  def test_empty(self):
    assert encode_base36(b"") == "0"
