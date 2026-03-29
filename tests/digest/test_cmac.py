"""Tests for AES-CMAC (RFC 4493) implementation.

Test vectors from RFC 4493 Section 4 and additional edge cases.
"""

from __future__ import annotations

from crypt.digest.HMAC.cmac import (
  _constant_time_compare,
  _generate_subkeys,
  _left_shift_block,
  cmac,
  cmac_verify,
)

import pytest

# RFC 4493 Section 4 test vectors
# All use the same AES-128 key
RFC4493_KEY: bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

# Subkey derivation test vectors (Section 4.1)
RFC4493_EXPECTED_K1: bytes = bytes.fromhex("fbeed618357133667c85e08f7236a8de")
RFC4493_EXPECTED_K2: bytes = bytes.fromhex("f7ddac306ae266ccf90bc11ee46d513b")

# CMAC test vectors (Section 4.2)
RFC4493_TEST_VECTORS: list[tuple[bytes, bytes, str]] = [
  # Example 1: empty message (len = 0)
  (
    RFC4493_KEY,
    b"",
    "bb1d6929e95937287fa37d129b756746",
  ),
  # Example 2: len = 16 (one full block)
  (
    RFC4493_KEY,
    bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
    "070a16b46b4d4144f79bdd9dd04a287c",
  ),
  # Example 3: len = 40 (two full blocks + partial)
  (
    RFC4493_KEY,
    bytes.fromhex(
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"
    ),
    "dfa66747de9ae63030ca32611497c827",
  ),
  # Example 4: len = 64 (four full blocks)
  (
    RFC4493_KEY,
    bytes.fromhex(
      "6bc1bee22e409f96e93d7e117393172a"
      "ae2d8a571e03ac9c9eb76fac45af8e51"
      "30c81c46a35ce411e5fbc1191a0a52ef"
      "f69f2445df4f9b17ad2b417be66c3710"
    ),
    "51f0bebf7e3b9d92fc49741779363cfe",
  ),
]


class TestCmacRFC4493:
  """Tests against RFC 4493 official test vectors."""

  def test_subkey_generation(self) -> None:
    """Test subkey derivation matches RFC 4493 Section 4.1."""
    k1, k2 = _generate_subkeys(RFC4493_KEY)
    assert k1 == RFC4493_EXPECTED_K1
    assert k2 == RFC4493_EXPECTED_K2

  @pytest.mark.parametrize(("key", "message", "expected_hex"), RFC4493_TEST_VECTORS)
  def test_rfc4493_vectors(self, key: bytes, message: bytes, expected_hex: str) -> None:
    """Test CMAC against RFC 4493 Section 4.2 test vectors."""
    result = cmac(key, message)
    assert result.hex() == expected_hex


class TestCmacAES256:
  """Tests for AES-256-CMAC (key = 32 bytes)."""

  def test_aes256_empty_message(self) -> None:
    """Test AES-256-CMAC with empty message."""
    key = bytes(32)  # 32 zero bytes
    result = cmac(key, b"")
    assert len(result) == 16

  def test_aes256_short_message(self) -> None:
    """Test AES-256-CMAC with a short message."""
    key = bytes(32)
    result = cmac(key, b"hello world")
    assert len(result) == 16

  def test_aes256_exact_block(self) -> None:
    """Test AES-256-CMAC with a message exactly one block."""
    key = bytes(32)
    result = cmac(key, bytes(16))
    assert len(result) == 16

  def test_aes256_multiple_blocks(self) -> None:
    """Test AES-256-CMAC with multiple blocks."""
    key = bytes(32)
    result = cmac(key, bytes(48))
    assert len(result) == 16


class TestCmacAES192:
  """Tests for AES-192-CMAC (key = 24 bytes)."""

  def test_aes192_empty_message(self) -> None:
    """Test AES-192-CMAC with empty message."""
    key = bytes(24)
    result = cmac(key, b"")
    assert len(result) == 16

  def test_aes192_short_message(self) -> None:
    """Test AES-192-CMAC with a short message."""
    key = bytes(24)
    result = cmac(key, b"test message")
    assert len(result) == 16


class TestCmacVerify:
  """Tests for cmac_verify function."""

  @pytest.mark.parametrize(("key", "message", "expected_hex"), RFC4493_TEST_VECTORS)
  def test_verify_valid_tag(
    self, key: bytes, message: bytes, expected_hex: str
  ) -> None:
    """Test that valid tags are accepted."""
    tag = bytes.fromhex(expected_hex)
    assert cmac_verify(key, message, tag) is True

  def test_verify_invalid_tag(self) -> None:
    """Test that invalid tags are rejected."""
    key = RFC4493_KEY
    message = b"test message"
    tag = cmac(key, message)
    # Flip one bit
    bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
    assert cmac_verify(key, message, bad_tag) is False

  def test_verify_wrong_length_tag(self) -> None:
    """Test that tags with wrong length are rejected."""
    key = RFC4493_KEY
    message = b"test"
    short_tag = b"\x00" * 8
    assert cmac_verify(key, message, short_tag) is False

  def test_verify_empty_message(self) -> None:
    """Test verification of empty message CMAC."""
    tag = bytes.fromhex("bb1d6929e95937287fa37d129b756746")
    assert cmac_verify(RFC4493_KEY, b"", tag) is True


class TestCmacEdgeCases:
  """Edge case tests for CMAC."""

  def test_invalid_key_length(self) -> None:
    """Test that invalid key lengths raise ValueError."""
    with pytest.raises(ValueError, match="Invalid key length"):
      cmac(b"\x00" * 15, b"test")

    with pytest.raises(ValueError, match="Invalid key length"):
      cmac(b"\x00" * 31, b"test")

  def test_deterministic(self) -> None:
    """Test that CMAC is deterministic."""
    key = RFC4493_KEY
    message = b"deterministic test"
    assert cmac(key, message) == cmac(key, message)

  def test_different_keys_different_tags(self) -> None:
    """Test that different keys produce different tags."""
    message = b"same message"
    key1 = bytes(16)
    key2 = bytes(16)
    key2 = key2[:15] + b"\x01"
    assert cmac(key1, message) != cmac(key2, message)

  def test_different_messages_different_tags(self) -> None:
    """Test that different messages produce different tags."""
    key = RFC4493_KEY
    assert cmac(key, b"message1") != cmac(key, b"message2")

  def test_large_message(self) -> None:
    """Test CMAC with a large message."""
    key = RFC4493_KEY
    message = b"x" * 10000
    result = cmac(key, message)
    assert len(result) == 16

  def test_all_byte_values(self) -> None:
    """Test CMAC with message containing all byte values."""
    key = RFC4493_KEY
    message = bytes(range(256))
    result = cmac(key, message)
    assert len(result) == 16


class TestConstantTimeCompare:
  """Tests for constant-time comparison function."""

  def test_equal_strings(self) -> None:
    """Test equal strings return True."""
    assert _constant_time_compare(b"abc", b"abc") is True

  def test_unequal_strings(self) -> None:
    """Test unequal strings return False."""
    assert _constant_time_compare(b"abc", b"abd") is False

  def test_different_lengths(self) -> None:
    """Test strings of different lengths return False."""
    assert _constant_time_compare(b"ab", b"abc") is False

  def test_empty_strings(self) -> None:
    """Test empty strings are equal."""
    assert _constant_time_compare(b"", b"") is True

  def test_one_empty(self) -> None:
    """Test one empty string returns False."""
    assert _constant_time_compare(b"a", b"") is False


class TestLeftShiftBlock:
  """Tests for the left-shift block operation."""

  def test_no_carry(self) -> None:
    """Test left shift when MSB is not set."""
    block = bytes(16)
    result = _left_shift_block(block)
    assert result == bytes(16)

  def test_with_carry(self) -> None:
    """Test left shift when MSB is set (triggers Rb XOR)."""
    block = bytes([0x80] + [0x00] * 15)
    result = _left_shift_block(block)
    # 0x80 << 1 = 0x00 with carry, last byte XOR 0x87
    expected = bytearray(16)
    expected[-1] = 0x87
    assert result == bytes(expected)

  def test_propagation(self) -> None:
    """Test carry propagation across bytes (right-to-left shift)."""
    # Block with 0x01 at byte 0: shift right-to-left, carry propagates to byte 1
    block = bytes([0x01] + [0x00] * 15)
    result = _left_shift_block(block)
    # byte 15..1: all 0x00, carry=0 → 0x00
    # byte 0: 0x01 << 1 = 0x02, carry=0
    expected = bytearray(16)
    expected[0] = 0x02
    assert result == bytes(expected)

  def test_carry_propagation_to_next_byte(self) -> None:
    """Test carry from right byte propagates to left byte."""
    # 0x80 at byte 15: shift → 0x00 with carry=1 into byte 14
    block = bytes([0x00] * 15 + [0x80])
    result = _left_shift_block(block)
    expected = bytearray(16)
    expected[14] = 0x01  # carry from byte 15
    assert result == bytes(expected)
