"""Tests for ANSI X.923 padding implementation."""

from crypt.encrypt.symmetric_encrypt.padding.ansi_x923 import pad, unpad

import pytest


class TestANSIX923Pad:
  """Tests for the pad function."""

  def test_pad_empty(self):
    """Empty data gets full block of padding."""
    result = pad(b"", 16)
    # 16 bytes of padding: zeros + last byte = 0x10
    assert result == b"\x00" * 15 + b"\x10"

  def test_pad_short_block(self):
    """Short data gets correct padding."""
    result = pad(b"hello", 16)
    # 5 bytes of data, 11 bytes of padding: zeros + last byte = 0x0b
    assert result == b"hello" + b"\x00" * 10 + b"\x0b"

  def test_pad_exact_block(self):
    """Exact block gets additional full block of padding."""
    data = b"a" * 16
    result = pad(data, 16)
    # Original 16 bytes plus 16 bytes of padding: zeros + last byte = 0x10
    assert result == data + b"\x00" * 15 + b"\x10"

  def test_pad_invalid_block_size_zero(self):
    """Block size 0 raises ValueError."""
    with pytest.raises(ValueError, match="block_size"):
      pad(b"hello", 0)

  def test_pad_invalid_block_size_256(self):
    """Block size 256 raises ValueError."""
    with pytest.raises(ValueError, match="block_size"):
      pad(b"hello", 256)

  def test_pad_invalid_block_size_negative(self):
    """Negative block size raises ValueError."""
    with pytest.raises(ValueError, match="block_size"):
      pad(b"hello", -1)


class TestANSIX923Unpad:
  """Tests for the unpad function."""

  def test_unpad_empty(self):
    """Empty data raises ValueError."""
    with pytest.raises(ValueError, match="empty"):
      unpad(b"", 16)

  def test_unpad_invalid_length(self):
    """Invalid padding length raises ValueError."""
    # Data shorter than padding length indicated
    with pytest.raises(ValueError, match="padding"):
      unpad(b"\x10", 16)  # Claims 16 bytes of padding but only 1 byte

  def test_unpad_invalid_padding_bytes(self):
    """Non-zero padding bytes (except last) raise ValueError."""
    # Padding bytes should be zeros, but we have non-zero bytes
    with pytest.raises(ValueError, match="padding"):
      unpad(b"hello\x03\x03\x03", 8)  # All bytes should be checked

  def test_unpad_zero_padding(self):
    """Zero padding byte raises ValueError."""
    with pytest.raises(ValueError, match="padding"):
      unpad(b"hello\x00", 8)

  def test_unpad_single_byte(self):
    """Unpad single byte of padding."""
    # For block_size=8, "hello" is 5 bytes, needs 3 bytes padding: \x00\x00\x03
    result = unpad(b"hello\x00\x00\x03", 8)
    assert result == b"hello"

  def test_unpad_full_block(self):
    """Unpad full block of padding."""
    data = b"a" * 16 + b"\x00" * 15 + b"\x10"
    result = unpad(data, 16)
    assert result == b"a" * 16


class TestANSIX923RoundTrip:
  """Round-trip tests for pad and unpad."""

  @pytest.mark.parametrize("block_size", [8, 16, 32])
  @pytest.mark.parametrize("data_length", [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100])
  def test_round_trip(self, block_size, data_length):
    """Pad and unpad should return original data."""
    data = b"x" * data_length
    padded = pad(data, block_size)
    unpadded = unpad(padded, block_size)
    assert unpadded == data
