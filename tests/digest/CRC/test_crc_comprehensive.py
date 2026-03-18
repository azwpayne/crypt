# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_crc_comprehensive.py
# @time    : 2026/3/17
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Comprehensive tests for CRC algorithms

"""
Comprehensive test suite for CRC (Cyclic Redundancy Check) algorithms.

Tests include:
- Known test vectors from official specifications
- Cross-validation between table-based and bit-by-bit implementations
- Various data lengths and patterns
- All standard CRC8 variants
- CRC32 implementation
"""

from __future__ import annotations

import zlib
from crypt.digest.CRC.crc8 import (
  crc8,
  crc8_autosar,
  crc8_bluetooth,
  crc8_j1850,
  crc8_lte,
  crc8_manual_calculation,
  crc8_maxim,
  crc8_smbus,
  reverse_bits,
)
from crypt.digest.CRC.crc32 import calculate_crc32

import pytest

# Standard test vector used by most CRC specifications
STANDARD_TEST_STRING = b"123456789"


class TestCRC8:
  """Test cases for CRC8 algorithms."""

  @pytest.mark.parametrize(
    ("func", "expected"),
    [
      (crc8_maxim, 0xA1),
      (crc8_autosar, 0xDF),
      (crc8_lte, 0xEA),
      (crc8_smbus, 0xF4),
      (crc8_bluetooth, 0x26),
      (crc8_j1850, 0x4B),
    ],
  )
  def test_crc8_known_vectors(self, func, expected):
    """Test CRC8 variants against known test vectors."""
    result = func(STANDARD_TEST_STRING)
    assert result == expected, (
      f"{func.__name__} failed: expected 0x{expected:02X}, got 0x{result:02X}"
    )

  def test_crc8_empty_data(self):
    """Test CRC8 with empty data."""
    # For empty data, crc8_smbus (init=0, xor_out=0) returns 0
    assert crc8_smbus(b"") == 0x00
    # For crc8_autosar: init=0xFF, xor_out=0xFF, so 0xFF ^ 0xFF = 0
    assert crc8_autosar(b"") == 0x00

  def test_crc8_single_byte(self):
    """Test CRC8 with single byte data."""
    data = b"A"

    # SMBUS with single byte 'A' (0x41)
    result = crc8_smbus(data)
    assert isinstance(result, int)
    assert 0 <= result <= 255

  def test_crc8_large_data(self):
    """Test CRC8 with large data."""
    data = b"A" * 10000

    result = crc8_maxim(data)
    assert isinstance(result, int)
    assert 0 <= result <= 255

  def test_crc8_binary_data(self):
    """Test CRC8 with binary data containing all byte values."""
    data = bytes(range(256))

    result = crc8_smbus(data)
    assert isinstance(result, int)
    assert 0 <= result <= 255

  def test_crc8_cross_validation(self):
    """Cross-validate table-based vs bit-by-bit implementation."""
    test_data = b"Hello, CRC8 World!"

    # Test multiple CRC variants
    variants = [
      (0x07, 0x00, False, False, 0x00),  # SMBUS-like
      (0x31, 0x00, True, True, 0x00),  # MAXIM-like
      (0x2F, 0xFF, False, False, 0xFF),  # AUTOSAR-like
    ]

    for poly, init, ref_in, ref_out, xor_out in variants:
      table_result = crc8(
        test_data, poly, init, ref_in=ref_in, ref_out=ref_out, xor_out=xor_out
      )
      manual_result = crc8_manual_calculation(
        test_data, poly, init, ref_in=ref_in, ref_out=ref_out, xor_out=xor_out
      )
      assert table_result == manual_result, (
        f"Cross-validation failed for poly=0x{poly:02X}"
      )

  def test_crc8_unicode_data(self):
    """Test CRC8 with UTF-8 encoded data."""
    data = "Hello, 世界!".encode()

    result = crc8_smbus(data)
    assert isinstance(result, int)
    assert 0 <= result <= 255

  def test_crc8_deterministic(self):
    """Test that CRC8 is deterministic (same input = same output)."""
    data = b"test data"

    result1 = crc8_maxim(data)
    result2 = crc8_maxim(data)

    assert result1 == result2

  def test_crc8_different_data(self):
    """Test that different data produces different CRCs."""
    data1 = b"data1"
    data2 = b"data2"

    crc1 = crc8_smbus(data1)
    crc2 = crc8_smbus(data2)

    assert crc1 != crc2

  def test_crc8_all_zeros(self):
    """Test CRC8 with all zeros data."""
    data = b"\x00" * 100

    result = crc8_smbus(data)
    assert isinstance(result, int)
    assert 0 <= result <= 255

  def test_crc8_all_ones(self):
    """Test CRC8 with all 0xFF data."""
    data = b"\xff" * 100

    result = crc8_smbus(data)
    assert isinstance(result, int)
    assert 0 <= result <= 255


class TestCRC8ReverseBits:
  """Test cases for bit reversal utility."""

  def test_reverse_bits_basic(self):
    """Test basic bit reversal."""
    assert reverse_bits(0x00) == 0x00
    assert reverse_bits(0xFF) == 0xFF
    assert reverse_bits(0x01) == 0x80
    assert reverse_bits(0x80) == 0x01

  def test_reverse_bits_pattern(self):
    """Test bit reversal with patterns."""
    # 0b10101010 -> 0b01010101
    assert reverse_bits(0xAA) == 0x55
    # 0b01010101 -> 0b10101010
    assert reverse_bits(0x55) == 0xAA
    # 0b11110000 -> 0b00001111
    assert reverse_bits(0xF0) == 0x0F


class TestCRC32:
  """Test cases for CRC32 algorithms."""

  def test_crc32_basic(self):
    """Test basic CRC32 calculation."""
    data = b"azwpayne"
    result = calculate_crc32(data)

    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_crc32_standard_vector(self):
    """Test CRC32 against standard test vector."""
    # Standard CRC32 of "123456789" should be 0xCBF43926
    result = calculate_crc32(STANDARD_TEST_STRING)
    expected = 0xCBF43926
    assert result == expected, (
      f"CRC32 mismatch: expected 0x{expected:08X}, got 0x{result:08X}"
    )

  def test_crc32_empty_data(self):
    """Test CRC32 with empty data."""
    result = calculate_crc32(b"")
    # Empty data CRC32 is 0x00000000 (after final XOR)
    expected = 0x00000000
    assert result == expected

  def test_crc32_single_byte(self):
    """Test CRC32 with single byte."""
    data = b"A"
    result = calculate_crc32(data)

    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_crc32_large_data(self):
    """Test CRC32 with large data."""
    data = b"A" * 100000
    result = calculate_crc32(data)

    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_crc32_binary_data(self):
    """Test CRC32 with binary data containing all byte values."""
    data = bytes(range(256))
    result = calculate_crc32(data)

    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_crc32_against_zlib(self):
    """Test CRC32 against Python's zlib implementation."""
    test_cases = [
      b"",
      b"A",
      b"Hello, World!",
      b"123456789",
      b"The quick brown fox jumps over the lazy dog",
      bytes(range(256)),
    ]

    for data in test_cases:
      our_result = calculate_crc32(data)
      # zlib.crc32 returns signed 32-bit, convert to unsigned
      zlib_result = zlib.crc32(data) & 0xFFFFFFFF
      assert our_result == zlib_result, (
        f"CRC32 mismatch for data {data!r}: "
        f"ours=0x{our_result:08X}, zlib=0x{zlib_result:08X}"
      )

  def test_crc32_deterministic(self):
    """Test that CRC32 is deterministic."""
    data = b"test data for crc32"

    result1 = calculate_crc32(data)
    result2 = calculate_crc32(data)

    assert result1 == result2

  def test_crc32_different_data(self):
    """Test that different data produces different CRCs."""
    data1 = b"data1"
    data2 = b"data2"

    crc1 = calculate_crc32(data1)
    crc2 = calculate_crc32(data2)

    assert crc1 != crc2

  def test_crc32_unicode_data(self):
    """Test CRC32 with UTF-8 encoded data."""
    data = "Hello, 世界! 🌍".encode()
    result = calculate_crc32(data)

    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

    # Cross-check with zlib
    zlib_result = zlib.crc32(data) & 0xFFFFFFFF
    assert result == zlib_result


class TestCRCEdgeCases:
  """Test edge cases and error handling."""

  def test_crc8_various_lengths(self):
    """Test CRC8 with various data lengths."""
    for length in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 1000]:
      data = b"X" * length
      result = crc8_smbus(data)
      assert isinstance(result, int)
      assert 0 <= result <= 255

  def test_crc32_various_lengths(self):
    """Test CRC32 with various data lengths."""
    for length in [0, 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 1000]:
      data = b"X" * length
      result = calculate_crc32(data)
      assert isinstance(result, int)
      assert 0 <= result <= 0xFFFFFFFF

  def test_crc8_special_bytes(self):
    """Test CRC8 with special byte patterns."""
    special_patterns = [
      b"\x00",  # Null byte
      b"\xff",  # All ones
      b"\x80",  # High bit set
      b"\x7f",  # Max positive
      b"\x55\xaa",  # Alternating bits
      b"\xaa\x55",  # Alternating bits reversed
    ]

    for pattern in special_patterns:
      result = crc8_smbus(pattern)
      assert isinstance(result, int)
      assert 0 <= result <= 255

  def test_crc32_special_bytes(self):
    """Test CRC32 with special byte patterns."""
    special_patterns = [
      b"\x00",
      b"\xff",
      b"\x80",
      b"\x7f",
      b"\x55\xaa",
      b"\xaa\x55",
      b"\xde\xad\xbe\xef",  # Dead beef
      b"\xca\xfe\xba\xbe",  # Cafe babe
    ]

    for pattern in special_patterns:
      result = calculate_crc32(pattern)
      zlib_result = zlib.crc32(pattern) & 0xFFFFFFFF
      assert result == zlib_result


class TestCRCConsistency:
  """Test consistency across multiple calls."""

  def test_crc8_multiple_calls(self):
    """Test that multiple calls produce consistent results."""
    data = b"consistency test data"

    results = [crc8_maxim(data) for _ in range(100)]
    assert all(r == results[0] for r in results)

  def test_crc32_multiple_calls(self):
    """Test that multiple calls produce consistent results."""
    data = b"consistency test data"

    results = [calculate_crc32(data) for _ in range(100)]
    assert all(r == results[0] for r in results)


class TestCRCustomParameters:
  """Test custom CRC parameters."""

  def test_crc8_custom_parameters(self):
    """Test CRC8 with custom parameters."""
    data = b"custom test"

    # Custom CRC8 with non-standard parameters
    result = crc8(
      data,
      poly=0x9B,  # Non-standard polynomial
      init=0xFF,  # Non-zero init
      ref_in=True,  # Reflect input
      ref_out=True,  # Reflect output
      xor_out=0x00,  # No final XOR
    )

    assert isinstance(result, int)
    assert 0 <= result <= 255

  def test_crc8_different_inits(self):
    """Test CRC8 with different init values."""
    data = b"test"

    inits = [0x00, 0xFF, 0xAA, 0x55]
    results = []

    for init in inits:
      result = crc8(
        data, poly=0x07, init=init, ref_in=False, ref_out=False, xor_out=0x00
      )
      results.append(result)

    # Different init values should produce different results
    assert len(set(results)) == len(results)
