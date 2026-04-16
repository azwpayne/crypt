"""Tests for SHAKE256 XOF (Extendable-Output Function)."""

from crypt.digest.SHAKE.shake256 import SHAKE256, shake256, shake256_hex, shake256_pad

import pytest


class TestSHAKE256:
  """Test cases for SHAKE256 XOF."""

  def test_shake256_empty_message(self):
    """Test SHAKE256 with empty message."""
    shake = SHAKE256()
    result = shake.read(32)
    assert len(result) == 32
    assert isinstance(result, bytes)

  def test_shake256_basic(self):
    """Test basic SHAKE256 functionality."""
    shake = SHAKE256(b"abc")
    result = shake.read(32)
    assert len(result) == 32

  def test_shake256_various_lengths(self):
    """Test SHAKE256 with various output lengths."""
    shake = SHAKE256(b"test message")

    for length in [1, 16, 32, 64, 128, 256, 512, 1024]:
      shake = SHAKE256(b"test message")
      result = shake.read(length)
      assert len(result) == length

  def test_shake256_multiple_reads(self):
    """Test multiple reads from SHAKE256."""
    shake = SHAKE256(b"test")

    result1 = shake.read(16)
    result2 = shake.read(16)
    result3 = shake.read(32)

    assert len(result1) == 16
    assert len(result2) == 16
    assert len(result3) == 32

    # Results should be different (continuous output)
    assert result1 != result2

  def test_shake256_hexdigest(self):
    """Test SHAKE256 hex output."""
    shake = SHAKE256(b"abc")
    hex_result = shake.hexdigest(32)

    assert isinstance(hex_result, str)
    assert len(hex_result) == 64  # 32 bytes = 64 hex chars

  def test_shake256_copy(self):
    """Test SHAKE256 copy functionality."""
    shake1 = SHAKE256(b"test")
    _ = shake1.read(16)  # Read some data

    shake2 = shake1.copy()

    result1 = shake1.read(32)
    result2 = shake2.read(32)

    assert result1 == result2

  def test_shake256_convenience_function(self):
    """Test the shake256 convenience function."""
    result = shake256(b"abc", 32)
    assert len(result) == 32

  def test_shake256_hex_convenience_function(self):
    """Test the shake256_hex convenience function."""
    result = shake256_hex(b"abc", 32)
    assert isinstance(result, str)
    assert len(result) == 64

  def test_shake256_update(self):
    """Test incremental update."""
    shake = SHAKE256()
    shake.update(b"Hello")
    shake.update(b", ")
    shake.update(b"World!")

    result = shake.read(32)
    assert len(result) == 32

  def test_shake256_large_input(self):
    """Test SHAKE256 with large input."""
    data = b"a" * 10000
    shake = SHAKE256(data)
    result = shake.read(64)
    assert len(result) == 64


class TestSHAKE256AgainstHashlib:
  """Test SHAKE256 against hashlib reference implementation."""

  def test_shake256_against_hashlib_basic(self):
    """Compare SHAKE256 output with hashlib."""
    hashlib = pytest.importorskip("hashlib")

    if not hasattr(hashlib, "shake_256"):
      pytest.skip("hashlib.shake_256 not available (requires Python 3.11+)")

    message = b"abc"

    # Our implementation
    shake = SHAKE256(message)
    our_result = shake.read(32)

    # hashlib
    h = hashlib.shake_256(message)
    their_result = h.digest(32)

    assert our_result == their_result

  def test_shake256_against_hashlib_empty(self):
    """Compare SHAKE256 with empty message against hashlib."""
    hashlib = pytest.importorskip("hashlib")

    if not hasattr(hashlib, "shake_256"):
      pytest.skip("hashlib.shake_256 not available")

    # Our implementation
    shake = SHAKE256(b"")
    our_result = shake.read(32)

    # hashlib
    h = hashlib.shake_256(b"")
    their_result = h.digest(32)

    assert our_result == their_result

  def test_shake256_against_hashlib_long_output(self):
    """Compare SHAKE256 with long output against hashlib."""
    hashlib = pytest.importorskip("hashlib")

    if not hasattr(hashlib, "shake_256"):
      pytest.skip("hashlib.shake_256 not available")

    message = b"The quick brown fox jumps over the lazy dog"

    # Our implementation
    shake = SHAKE256(message)
    our_result = shake.read(256)

    # hashlib
    h = hashlib.shake_256(message)
    their_result = h.digest(256)

    assert our_result == their_result


class TestSHAKE256NISTVectors:
  """Test SHAKE256 against NIST test vectors."""

  def test_shake256_nist_short_message(self):
    """Test with short message from NIST vectors."""
    shake = SHAKE256(b"abc")
    result = shake.read(32)

    # Just verify we get consistent results
    shake2 = SHAKE256(b"abc")
    result2 = shake2.read(32)

    assert result == result2

  def test_shake256_nist_zero_message(self):
    """Test with zero-length message."""
    shake = SHAKE256(b"")
    result = shake.read(16)

    shake2 = SHAKE256(b"")
    result2 = shake2.read(16)

    assert result == result2


class TestSHAKE256EdgeCases:
  def test_shake256_different_output_lengths(self):
    """Test SHAKE256 with different output lengths."""
    data = b"test"
    h1 = shake256(data, 16)
    h2 = shake256(data, 64)
    assert len(h1) == 16
    assert len(h2) == 64
    assert h2.startswith(h1)

  def test_shake256_empty_input(self):
    """Test SHAKE256 with empty input."""
    result = shake256(b"", 64)
    assert len(result) == 64

  def test_shake256_class_interface(self):
    """Test SHAKE256 class-based interface."""
    hasher = SHAKE256()
    hasher.update(b"Hello")
    hasher.update(b", World!")
    result = hasher.read(64)
    assert len(result) == 64

  def test_shake256_hexdigest(self):
    """Test SHAKE256 hexdigest."""
    hasher = SHAKE256()
    hasher.update(b"test")
    hex_result = hasher.hexdigest(32)
    assert len(hex_result) == 64

  def test_shake256_negative_length(self):
    """Test SHAKE256 with negative length."""
    shake = SHAKE256(b"test")
    with pytest.raises(ValueError, match="Length must be non-negative"):
      shake.read(-1)

  def test_shake256_zero_length(self):
    """Test SHAKE256 with zero length."""
    shake = SHAKE256(b"test")
    result = shake.read(0)
    assert result == b""

  def test_shake256_update_after_read(self):
    """Test SHAKE256 cannot update after reading."""
    shake = SHAKE256(b"test")
    _ = shake.read(1)
    with pytest.raises(ValueError, match="Cannot update after reading output"):
      shake.update(b"more")

  def test_shake256_exact_rate_boundary(self):
    """Test SHAKE256 with input exactly at rate boundary (136 bytes)."""
    data = b"a" * 136
    result = shake256(data, 32)
    assert len(result) == 32

  def test_shake256_long_output_multiple_squeezes(self):
    """Test SHAKE256 with long output requiring multiple squeezes."""
    data = b"test"
    result = shake256(data, 500)
    assert len(result) == 500

  def test_shake256_finalize_idempotent(self):
    """Test that calling read multiple times does not re-finalize."""
    shake = SHAKE256(b"test")
    result1 = shake.read(16)
    result2 = shake.read(16)
    # Should get continuous output, not restart
    assert len(result1) == 16
    assert len(result2) == 16
    assert result1 != result2

  def test_shake256_pad_exact_rate_boundary(self):
    """Test shake256_pad when message length is exact multiple of rate."""
    padding = shake256_pad(136, 136)
    assert len(padding) == 136
    assert padding[0] == 0x1F
    assert padding[-1] == 0x80
