# @author  : azwpayne(https://github.com/azwpayne)  # noqa: INP001
# @name    : test_md5.py
# @time    : 2026/3/13
# @desc    : Tests for MD5 digest
import hashlib
from crypt.digest.MD import md5

import pytest

from tests import BYTE_TEST_CASES


class TestMD5:
  """Test MD5 implementation against hashlib reference."""

  # RFC 1321 test vectors
  RFC1321_TEST_VECTORS = [  # noqa: RUF012
    (b"", "d41d8cd98f00b204e9800998ecf8427e"),
    (b"a", "0cc175b9c0f1b6a831c399e269772661"),
    (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
    (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
    (b"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
    (
      b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "d174ab98d277d9f5a5611c2c9f419d9f",
    ),
    (
      b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "57edf4a22be3c955ac49da2e2107b67a",
    ),
  ]

  @pytest.mark.parametrize(("msg", "expected"), RFC1321_TEST_VECTORS)
  def test_md5_rfc1321_vectors(self, msg, expected):
    """Verify MD5 against RFC 1321 test vectors."""
    result = md5.md5(msg)
    assert result == expected, f"MD5 mismatch for: {msg!r}"

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_md5_vs_hashlib(self, msg):
    """Verify MD5 implementation matches hashlib output."""
    # BYTE_TEST_CASES already contains bytes
    custom_result = md5.md5(msg)
    hashlib_result = hashlib.md5(msg).hexdigest()
    assert custom_result == hashlib_result, f"Mismatch for: {msg!r}"

  def test_md5_string_input(self):
    """Test MD5 with string input."""
    result = md5.md5("hello")
    expected = hashlib.md5(b"hello").hexdigest()
    assert result == expected

  def test_md5_bytes_input(self):
    """Test MD5 with bytes input."""
    result = md5.md5(b"hello")
    expected = hashlib.md5(b"hello").hexdigest()
    assert result == expected

  def test_md5_empty(self):
    """Test MD5 with empty input."""
    result = md5.md5(b"")
    expected = "d41d8cd98f00b204e9800998ecf8427e"
    assert result == expected

  def test_md5_large_input(self):
    """Test MD5 with large input."""
    data = b"a" * 10000
    custom_result = md5.md5(data)
    hashlib_result = hashlib.md5(data).hexdigest()
    assert custom_result == hashlib_result

  def test_md5_binary_data(self):
    """Test MD5 with binary data."""
    data = bytes(range(256))
    custom_result = md5.md5(data)
    hashlib_result = hashlib.md5(data).hexdigest()
    assert custom_result == hashlib_result


class TestMD5Helpers:
  """Test MD5 helper functions."""

  def test_left_rotate(self):
    """Test left rotate function."""
    # 0b10110000 rotated left by 2 = 0b11000010
    result = md5.left_rotate(0b10110000, 2)
    expected = ((0b10110000 << 2) | (0b10110000 >> (32 - 2))) & 0xFFFFFFFF
    assert result == expected

  def test_bitwise_choice(self):
    """Test bitwise choice function."""
    # mask=1 -> if_true, mask=0 -> if_false
    mask = 0b1010
    if_true = 0b1111
    if_false = 0b0000
    result = md5.bitwise_choice(mask, if_true, if_false)
    # Expected: 1 positions -> if_true(1), 0 positions -> if_false(0)
    # mask 1010, if_true 1111, if_false 0000 -> result 1010
    expected = 0b1010
    assert result == expected

  def test_bitwise_majority(self):
    """Test bitwise majority function."""
    # Majority of three bits
    x, y, z = 0b1010, 0b1100, 0b1000
    result = md5.bitwise_majority(x, y, z)
    # For each bit position, majority of (x,y,z)
    # bit 3: (1,1,1) -> 1
    # bit 2: (0,1,1) -> 1
    # bit 1: (1,0,0) -> 0
    # bit 0: (0,0,0) -> 0
    expected = 0b1000
    assert result == expected

  def test_bitwise_xor3(self):
    """Test bitwise XOR function."""
    x, y, z = 0b1010, 0b1100, 0b1000
    result = md5.bitwise_xor3(x, y, z)
    # MD5 HH function uses x ^ y ^ z (XOR of three inputs)
    expected = (x ^ y ^ z) & 0xFFFFFFFF
    assert result == expected

  def test_bitwise_nor_mix(self):
    """Test bitwise nor mix function."""
    x, y, z = 0b1010, 0b1100, 0b1000
    result = md5.bitwise_nor_mix(x, y, z)
    # y ^ (x | (0xFFFFFFFF ^ z))
    expected = (y ^ (x | (0xFFFFFFFF ^ z))) & 0xFFFFFFFF
    assert result == expected


class TestMD5Padding:
  """Test MD5 padding function."""

  def test_pad_message_empty(self):
    """Test padding of empty message."""
    result = md5.pad_message(b"")
    # Should add 0x80 + padding to 56 mod 64, then 8 bytes length
    assert len(result) == 64
    assert result[0] == 0x80
    # Length in bits (0) as 8-byte little-endian at end
    assert result[-8:] == b"\x00\x00\x00\x00\x00\x00\x00\x00"

  def test_pad_message_short(self):
    """Test padding of short message."""
    msg = b"abc"
    result = md5.pad_message(msg)
    assert result.startswith(b"abc\x80")
    assert len(result) % 64 == 0

  def test_pad_message_length(self):
    """Test that padding adds correct length."""
    msg = b"a" * 55  # Just fits in one block
    result = md5.pad_message(msg)
    assert len(result) == 64

    msg = b"a" * 56  # Needs another block
    result = md5.pad_message(msg)
    assert len(result) == 128

  def test_pad_message_length_encoding(self):
    """Test that message length is correctly encoded."""
    msg = b"abc"
    result = md5.pad_message(msg)
    # Length in bits: 3 * 8 = 24 = 0x18
    assert result[-8] == 24  # Little-endian
