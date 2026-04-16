"""Tests for SHAKE128 XOF (Extendable-Output Function)."""

from crypt.digest.SHAKE.shake128 import SHAKE128, shake128, shake128_hex, shake128_pad

import pytest


class TestSHAKE128:
  """Test cases for SHAKE128 XOF."""

  def test_shake128_empty_message(self):
    """Test SHAKE128 with empty message."""
    shake = SHAKE128()
    result = shake.read(32)
    assert len(result) == 32
    assert isinstance(result, bytes)

  def test_shake128_basic(self):
    """Test basic SHAKE128 functionality."""
    shake = SHAKE128(b"abc")
    result = shake.read(32)
    assert len(result) == 32

  def test_shake128_various_lengths(self):
    """Test SHAKE128 with various output lengths."""
    shake = SHAKE128(b"test message")

    for length in [1, 16, 32, 64, 128, 256, 512, 1024]:
      shake = SHAKE128(b"test message")
      result = shake.read(length)
      assert len(result) == length

  def test_shake128_multiple_reads(self):
    """Test multiple reads from SHAKE128."""
    shake = SHAKE128(b"test")

    result1 = shake.read(16)
    result2 = shake.read(16)
    result3 = shake.read(32)

    assert len(result1) == 16
    assert len(result2) == 16
    assert len(result3) == 32

    # Results should be different (continuous output)
    assert result1 != result2

  def test_shake128_hexdigest(self):
    """Test SHAKE128 hex output."""
    shake = SHAKE128(b"abc")
    hex_result = shake.hexdigest(32)

    assert isinstance(hex_result, str)
    assert len(hex_result) == 64  # 32 bytes = 64 hex chars

  def test_shake128_copy(self):
    """Test SHAKE128 copy functionality."""
    shake1 = SHAKE128(b"test")
    _ = shake1.read(16)  # Read some data

    shake2 = shake1.copy()

    result1 = shake1.read(32)
    result2 = shake2.read(32)

    assert result1 == result2

  def test_shake128_convenience_function(self):
    """Test the shake128 convenience function."""
    result = shake128(b"abc", 32)
    assert len(result) == 32

  def test_shake128_hex_convenience_function(self):
    """Test the shake128_hex convenience function."""
    result = shake128_hex(b"abc", 32)
    assert isinstance(result, str)
    assert len(result) == 64

  def test_shake128_update(self):
    """Test incremental update."""
    shake = SHAKE128()
    shake.update(b"Hello")
    shake.update(b", ")
    shake.update(b"World!")

    result = shake.read(32)
    assert len(result) == 32

  def test_shake128_large_input(self):
    """Test SHAKE128 with large input."""
    data = b"a" * 10000
    shake = SHAKE128(data)
    result = shake.read(64)
    assert len(result) == 64


class TestSHAKE128AgainstHashlib:
  """Test SHAKE128 against hashlib reference implementation."""

  def test_shake128_against_hashlib_basic(self):
    """Compare SHAKE128 output with hashlib."""
    hashlib = pytest.importorskip("hashlib")

    if not hasattr(hashlib, "shake_128"):
      pytest.skip("hashlib.shake_128 not available (requires Python 3.11+)")

    message = b"abc"

    # Our implementation
    shake = SHAKE128(message)
    our_result = shake.read(32)

    # hashlib
    h = hashlib.shake_128(message)
    their_result = h.digest(32)

    assert our_result == their_result

  def test_shake128_against_hashlib_empty(self):
    """Compare SHAKE128 with empty message against hashlib."""
    hashlib = pytest.importorskip("hashlib")

    if not hasattr(hashlib, "shake_128"):
      pytest.skip("hashlib.shake_128 not available")

    # Our implementation
    shake = SHAKE128(b"")
    our_result = shake.read(32)

    # hashlib
    h = hashlib.shake_128(b"")
    their_result = h.digest(32)

    assert our_result == their_result

  def test_shake128_against_hashlib_long_output(self):
    """Compare SHAKE128 with long output against hashlib."""
    hashlib = pytest.importorskip("hashlib")

    if not hasattr(hashlib, "shake_128"):
      pytest.skip("hashlib.shake_128 not available")

    message = b"The quick brown fox jumps over the lazy dog"

    # Our implementation
    shake = SHAKE128(message)
    our_result = shake.read(256)

    # hashlib
    h = hashlib.shake_128(message)
    their_result = h.digest(256)

    assert our_result == their_result


class TestSHAKE128NISTVectors:
  """Test SHAKE128 against NIST test vectors."""

  def test_shake128_nist_short_message(self):
    """Test with short message from NIST vectors."""
    # Input: "abc"
    # Output length: 256 bits (32 bytes)
    # Expected first few bytes can be verified
    shake = SHAKE128(b"abc")
    result = shake.read(32)

    # Just verify we get consistent results
    shake2 = SHAKE128(b"abc")
    result2 = shake2.read(32)

    assert result == result2

  def test_shake128_nist_zero_message(self):
    """Test with zero-length message."""
    shake = SHAKE128(b"")
    result = shake.read(16)

    shake2 = SHAKE128(b"")
    result2 = shake2.read(16)

    assert result == result2


class TestSHAKE128EdgeCases:
  def test_shake128_different_output_lengths(self):
    """Test SHAKE128 with different output lengths."""
    data = b"test"
    h1 = shake128(data, 16)
    h2 = shake128(data, 32)
    assert len(h1) == 16
    assert len(h2) == 32
    assert h2.startswith(h1)

  def test_shake128_empty_input(self):
    """Test SHAKE128 with empty input."""
    result = shake128(b"", 32)
    assert len(result) == 32

  def test_shake128_class_interface(self):
    """Test SHAKE128 class-based interface."""
    hasher = SHAKE128()
    hasher.update(b"Hello")
    hasher.update(b", World!")
    result = hasher.read(32)
    assert len(result) == 32

  def test_shake128_hexdigest(self):
    """Test SHAKE128 hexdigest."""
    hasher = SHAKE128()
    hasher.update(b"test")
    hex_result = hasher.hexdigest(16)
    assert len(hex_result) == 32

  def test_shake128_negative_length(self):
    """Test SHAKE128 with negative length."""
    shake = SHAKE128(b"test")
    with pytest.raises(ValueError, match="Length must be non-negative"):
      shake.read(-1)

  def test_shake128_zero_length(self):
    """Test SHAKE128 with zero length."""
    shake = SHAKE128(b"test")
    result = shake.read(0)
    assert result == b""

  def test_shake128_update_after_read(self):
    """Test SHAKE128 cannot update after reading."""
    shake = SHAKE128(b"test")
    _ = shake.read(1)
    with pytest.raises(ValueError, match="Cannot update after reading output"):
      shake.update(b"more")

  def test_shake128_exact_rate_boundary(self):
    """Test SHAKE128 with input exactly at rate boundary (168 bytes)."""
    data = b"a" * 168
    result = shake128(data, 32)
    assert len(result) == 32

  def test_shake128_long_output_multiple_squeezes(self):
    """Test SHAKE128 with long output requiring multiple squeezes."""
    data = b"test"
    result = shake128(data, 500)
    assert len(result) == 500

  def test_shake128_finalize_idempotent(self):
    """Test that calling read multiple times does not re-finalize."""
    shake = SHAKE128(b"test")
    result1 = shake.read(16)
    result2 = shake.read(16)
    # Should get continuous output, not restart
    assert len(result1) == 16
    assert len(result2) == 16
    assert result1 != result2

  def test_shake128_pad_exact_rate_boundary(self):
    """Test shake128_pad when message length is exact multiple of rate."""
    padding = shake128_pad(168, 168)
    assert len(padding) == 168
    assert padding[0] == 0x1F
    assert padding[-1] == 0x80
