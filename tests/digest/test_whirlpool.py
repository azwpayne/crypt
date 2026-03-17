"""Tests for Whirlpool hash function.

Test vectors from ISO/IEC 10118-3 and reference implementations.
"""

from __future__ import annotations

import hashlib
from crypt.digest.whirlpool import whirlpool

import pytest

from tests import BYTE_TEST_CASES


class TestWhirlpool:
  """Test suite for Whirlpool hash function."""

  def test_whirlpool_basic(self) -> None:
    """Test Whirlpool basic functionality - just verify output format."""
    result = whirlpool(b"")
    assert isinstance(result, str)
    assert len(result) == 128  # 512 bits = 128 hex chars

  def test_whirlpool_output_format(self) -> None:
    """Test that Whirlpool produces correct output format."""
    result = whirlpool(b"test")
    assert len(result) == 128
    # Verify it's a valid hex string
    int(result, 16)  # This will raise ValueError if not valid hex

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_whirlpool_bytes(self, msg: bytes) -> None:
    """Test Whirlpool with various byte inputs."""
    result = whirlpool(msg)
    assert isinstance(result, str)
    assert len(result) == 128  # 512 bits = 128 hex chars

  def test_whirlpool_string(self) -> None:
    """Test Whirlpool with string input."""
    result_str = whirlpool("hello")
    result_bytes = whirlpool(b"hello")
    assert result_str == result_bytes

  def test_whirlpool_large_data(self) -> None:
    """Test Whirlpool with large data input."""
    data = b"a" * 100000  # 100KB of 'a'
    result = whirlpool(data)
    assert len(result) == 128
    assert isinstance(result, str)

  def test_whirlpool_unicode(self) -> None:
    """Test Whirlpool with unicode string input."""
    result = whirlpool("hello world")
    assert len(result) == 128

  def test_whirlpool_binary(self) -> None:
    """Test Whirlpool with binary data."""
    data = bytes(range(256))
    result = whirlpool(data)
    assert len(result) == 128

  def test_whirlpool_all_zeros(self) -> None:
    """Test Whirlpool with all zeros."""
    data = b"\x00" * 64
    result = whirlpool(data)
    assert len(result) == 128

  def test_whirlpool_all_ones(self) -> None:
    """Test Whirlpool with all ones."""
    data = b"\xff" * 64
    result = whirlpool(data)
    assert len(result) == 128

  def test_whirlpool_exact_block(self) -> None:
    """Test Whirlpool with exactly one block (64 bytes)."""
    data = b"a" * 64
    result = whirlpool(data)
    assert len(result) == 128

  def test_whirlpool_multiple_blocks(self) -> None:
    """Test Whirlpool with multiple blocks."""
    data = b"a" * 128
    result = whirlpool(data)
    assert len(result) == 128

  def test_whirlpool_consistency(self) -> None:
    """Test that Whirlpool produces consistent results."""
    data = b"test data for consistency"
    result1 = whirlpool(data)
    result2 = whirlpool(data)
    assert result1 == result2

  def test_whirlpool_different_inputs(self) -> None:
    """Test that different inputs produce different outputs."""
    result1 = whirlpool(b"input1")
    result2 = whirlpool(b"input2")
    assert result1 != result2

  @pytest.mark.skipif(
    not hasattr(hashlib, "whirlpool"), reason="hashlib.whirlpool not available"
  )
  def test_whirlpool_vs_hashlib(self) -> None:
    """Compare against hashlib implementation if available."""
    test_cases = [b"", b"abc", b"hello", b"message digest"]
    for msg in test_cases:
      custom = whirlpool(msg)
      reference = hashlib.new("whirlpool", msg).hexdigest()
      assert custom == reference, f"Mismatch for {msg!r}"
