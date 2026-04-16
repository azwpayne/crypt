"""Tests for Base36 encoding."""

from crypt.encode.base36 import (
  base36_decode,
  base36_encode,
  decode_base36,
  encode_base36,
)

import pytest


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

  def test_base36_encode_negative(self):
    """Test that negative input raises ValueError."""
    with pytest.raises(ValueError, match="Only non-negative integers are supported"):
      base36_encode(-1)

  def test_base36_decode_invalid_char(self):
    """Test that invalid characters raise ValueError."""
    with pytest.raises(ValueError, match="Invalid Base36 character"):
      base36_decode("xyz!")

  def test_base36_decode_empty(self):
    """Test decoding empty string returns 0."""
    assert base36_decode("") == 0
    assert base36_decode("000") == 0

  def test_encode_base36_all_zeros(self):
    """Test encoding all-zero bytes."""
    assert encode_base36(b"\x00\x00\x00") == "0000"

  def test_decode_base36_all_zeros(self):
    """Test decoding all-zero string."""
    assert decode_base36("000") == b"\x00\x00\x00"

  def test_decode_base36_zero(self):
    """Test decoding '0' returns empty bytes."""
    assert decode_base36("0") == b""
