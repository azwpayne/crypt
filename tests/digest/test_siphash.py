"""Tests for SipHash-2-4 implementation.

Test vectors from the official SipHash reference implementation and OpenSSL.
Key = 000102030405060708090a0b0c0d0e0f for all vectors.
"""

from __future__ import annotations

from crypt.digest.siphash import siphash24, siphash24_int

import pytest

# Official SipHash-2-4 test vectors (64-bit / 8-byte output)
# Key = 000102030405060708090a0b0c0d0e0f
# Messages: bytes(range(n)) for n in 0..15, plus a 63-byte vector from OpenSSL.
SIPHASH24_TEST_VECTORS: list[tuple[int, bytes, str]] = [
  (0, b"", "310e0edd47db6f72"),
  (1, b"\x00", "fd67dc93c539f874"),
  (2, b"\x00\x01", "5a4fa9d909806c0d"),
  (3, b"\x00\x01\x02", "2d7efbd796666785"),
  (4, b"\x00\x01\x02\x03", "b7877127e09427cf"),
  (5, b"\x00\x01\x02\x03\x04", "8da699cd64557618"),
  (6, b"\x00\x01\x02\x03\x04\x05", "cee3fe586e46c9cb"),
  (7, b"\x00\x01\x02\x03\x04\x05\x06", "37d1018bf50002ab"),
  (8, b"\x00\x01\x02\x03\x04\x05\x06\x07", "6224939a79f5f593"),
  (9, b"\x00\x01\x02\x03\x04\x05\x06\x07\x08", "b0e4a90bdf82009e"),
  (10, b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", "f3b9dd94c5bb5d7a"),
  (11, b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a", "a7ad6b22462fb3f4"),
  (12, b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b", "fbe50e86bc8f1e75"),
  (13, b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c", "903d84c02756ea14"),
  (14, b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d", "eef27a8e90ca23f7"),
  (
    15,
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e",
    "e545be4961ca29a1",
  ),
  # 63-byte vector from OpenSSL test suite
  (63, bytes(range(0x3F)), "724506eb4c328a95"),
]


class TestSiphash24:
  """Tests for siphash24 (bytes output)."""

  @pytest.mark.parametrize(("length", "message", "expected"), SIPHASH24_TEST_VECTORS)
  def test_official_vectors(self, length: int, message: bytes, expected: str) -> None:
    """Test against official SipHash-2-4 test vectors."""
    key = bytes(range(16))
    assert len(message) == length
    result = siphash24(key, message).hex()
    assert result == expected

  def test_empty_message(self) -> None:
    """Test SipHash-2-4 with empty message."""
    key = bytes(range(16))
    assert siphash24(key, b"").hex() == "310e0edd47db6f72"

  def test_output_length(self) -> None:
    """Output must always be 8 bytes."""
    key = bytes(range(16))
    assert len(siphash24(key, b"")) == 8
    assert len(siphash24(key, b"a" * 1000)) == 8

  def test_different_keys_produce_different_tags(self) -> None:
    """Different keys must yield different tags for the same message."""
    msg = b"test message"
    tag1 = siphash24(bytes(16), msg)
    tag2 = siphash24(bytes(range(16)), msg)
    assert tag1 != tag2

  def test_deterministic(self) -> None:
    """Same key and message must always produce the same tag."""
    key = bytes(range(16))
    msg = b"deterministic"
    assert siphash24(key, msg) == siphash24(key, msg)

  def test_invalid_key_length(self) -> None:
    """Key must be exactly 16 bytes."""
    with pytest.raises(ValueError, match="Key must be 16 bytes"):
      siphash24(b"short", b"message")
    with pytest.raises(ValueError, match="Key must be 16 bytes"):
      siphash24(b"this key is way too long for siphash", b"message")


class TestSiphash24Int:
  """Tests for siphash24_int (integer output)."""

  @pytest.mark.parametrize(("length", "message", "expected"), SIPHASH24_TEST_VECTORS)
  def test_matches_bytes_output(
    self,
    length: int,
    message: bytes,
    expected: str,  # noqa: ARG002
  ) -> None:
    """Integer output must match the bytes output."""
    _ = length, expected  # used via parametrize
    key = bytes(range(16))
    int_result = siphash24_int(key, message)
    bytes_result = int.from_bytes(siphash24(key, message), "little")
    assert int_result == bytes_result

  def test_return_type(self) -> None:
    """Return value must be an int."""
    key = bytes(range(16))
    assert isinstance(siphash24_int(key, b""), int)

  def test_invalid_key_length(self) -> None:
    """Key must be exactly 16 bytes."""
    with pytest.raises(ValueError, match="Key must be 16 bytes"):
      siphash24_int(b"short", b"message")


class TestSiphashEdgeCases:
  """Edge case tests for SipHash-2-4."""

  def test_large_message(self) -> None:
    """Test with a large message (10 KB)."""
    key = bytes(range(16))
    msg = b"\xab" * 10_000
    tag = siphash24(key, msg)
    assert len(tag) == 8

  def test_all_zero_key(self) -> None:
    """Test with an all-zero key."""
    key = b"\x00" * 16
    tag = siphash24(key, b"test")
    assert len(tag) == 8
    assert tag != b"\x00" * 8

  def test_all_ff_key(self) -> None:
    """Test with an all-0xFF key."""
    key = b"\xff" * 16
    tag = siphash24(key, b"test")
    assert len(tag) == 8

  def test_single_byte_messages(self) -> None:
    """Each single-byte value should produce a unique tag."""
    key = bytes(range(16))
    tags = {siphash24(key, bytes([b])).hex() for b in range(256)}
    # All 256 single-byte messages should produce distinct tags
    assert len(tags) == 256

  def test_message_exactly_one_block(self) -> None:
    """Test with message exactly 8 bytes (one block)."""
    key = bytes(range(16))
    msg = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    assert siphash24(key, msg).hex() == "6224939a79f5f593"

  def test_message_exactly_two_blocks(self) -> None:
    """Test with message exactly 16 bytes (two blocks)."""
    key = bytes(range(16))
    msg = bytes(range(16))
    tag = siphash24(key, msg)
    assert len(tag) == 8
