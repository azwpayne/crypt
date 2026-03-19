"""Tests for base16 (hex) encoding/decoding."""

from __future__ import annotations

import binascii
from crypt.encode import base16

import pytest

from tests import BYTE_TEST_CASES


@pytest.mark.parametrize("msg", BYTE_TEST_CASES)
class TestBase16:
  """Test base16 encoding and decoding against Python standard library."""

  def test_base16_encode(self, msg):
    """Verify base16_encode matches standard library output."""
    result = base16.base16_encode(msg)
    expected = binascii.hexlify(msg).decode("ascii").upper()
    assert result == expected, f"Encoding failed for: {msg!r}"

  def test_base16_encode_lowercase(self, msg):
    """Verify base16_encode lowercase option."""
    result = base16.base16_encode(msg, uppercase=False)
    expected = binascii.hexlify(msg).decode("ascii").lower()
    assert result == expected, f"Lowercase encoding failed for: {msg!r}"

  def test_base16_decode(self, msg):
    """Verify base16_decode correctly decodes encoded data."""
    encoded = base16.base16_encode(msg)
    decoded = base16.base16_decode(encoded)
    assert decoded == msg, f"Decoding failed for: {msg!r}"

  def test_base16_roundtrip(self, msg):
    """Verify encode/decode roundtrip."""
    encoded = base16.base16_encode(msg)
    decoded = base16.base16_decode(encoded)
    assert decoded == msg, f"Roundtrip failed for: {msg!r}"


class TestBase16EdgeCases:
  """Test edge cases and error handling."""

  def test_base16_empty(self):
    """Test empty input."""
    assert base16.base16_encode(b"") == ""
    assert base16.base16_decode("") == b""

  def test_base16_whitespace_handling(self):
    """Test that whitespace is removed during decode."""
    # Space-separated hex
    assert base16.base16_decode("48 65 6C 6C 6F") == b"Hello"
    # Newline-separated hex
    assert base16.base16_decode("48\n65\n6C\n6C\n6F") == b"Hello"
    # Mixed whitespace
    assert base16.base16_decode("48 65\n6C\r\n6C 6F") == b"Hello"

  def test_base16_mixed_case_decode(self):
    """Test that mixed case is accepted during decode."""
    assert base16.base16_decode("48656c6c6f") == b"Hello"
    assert base16.base16_decode("48656C6C6F") == b"Hello"
    # Mixed case within bytes
    assert base16.base16_decode("48656C6c6F") == b"Hello"

  def test_base16_binary_data(self):
    """Test with various binary data patterns."""
    test_cases = [
      b"\x00" * 10,
      b"\xff" * 10,
      b"\x00\x01\x02\x03\x04\x05",
      bytes(range(256)),
    ]
    for data in test_cases:
      encoded = base16.base16_encode(data)
      decoded = base16.base16_decode(encoded)
      assert decoded == data, f"Failed for binary data: {data!r}"

  def test_base16_invalid_length(self):
    """Test that odd length input raises error."""
    with pytest.raises(ValueError, match="必须为偶数"):
      base16.base16_decode("123")  # Odd length

  def test_base16_invalid_char(self):
    """Test that invalid characters raise error."""
    with pytest.raises(ValueError, match="非法十六进制字符"):
      base16.base16_decode("GGGG")  # G is not valid hex

    with pytest.raises(ValueError, match="非法十六进制字符"):
      base16.base16_decode("123X")  # X is not valid hex

  def test_base16_single_byte(self):
    """Test encoding/decoding single bytes."""
    for i in range(256):
      data = bytes([i])
      encoded = base16.base16_encode(data)
      decoded = base16.base16_decode(encoded)
      assert decoded == data, f"Failed for byte value: {i}"
      assert len(encoded) == 2  # Single byte = 2 hex chars
