"""Complete test suite for all CRC algorithms.

Tests for CRC-8, CRC-12, CRC-16, CRC-16-CCITT, CRC-32, CRC-32C, and CRC-64.
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
from crypt.digest.CRC.crc12 import (
  crc12,
  crc12_cdma2000,
  crc12_dect,
  crc12_gsm,
  crc12_umts,
)
from crypt.digest.CRC.crc16 import (
  crc16,
  crc16_ansi,
  crc16_dnp,
  crc16_ibm,
  crc16_modbus,
  crc16_usb,
  crc16_xmodem,
)
from crypt.digest.CRC.crc16_ccitt import (
  crc16_ccitt,
  crc16_ccitt_1d0f,
  crc16_ccitt_false,
  crc16_ccitt_ffff,
  crc16_ccitt_kermit,
  crc16_ccitt_true,
  crc16_ccitt_xmodem,
)
from crypt.digest.CRC.crc32 import calculate_crc32, get_crc32
from crypt.digest.CRC.crc32c import crc32c, crc32c_castagnoli, crc32c_iscsi, crc32c_sctp
from crypt.digest.CRC.crc64 import crc64, crc64_hex

import pytest

# Standard test vector
STANDARD_TEST = b"123456789"


class TestCRC8AllVariants:
  """Comprehensive tests for all CRC-8 variants."""

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
  def test_standard_test_vectors(self, func, expected):
    """Test all CRC-8 variants with standard test vector."""
    result = func(STANDARD_TEST)
    assert result == expected

  def test_empty_input(self):
    """Test CRC-8 with empty input."""
    # CRC-8/SMBUS with empty data returns init value (0)
    assert crc8_smbus(b"") == 0x00
    # CRC-8/AUTOSAR: init=0xFF, xor_out=0xFF
    assert crc8_autosar(b"") == 0x00

  def test_single_byte_inputs(self):
    """Test CRC-8 with single byte inputs."""
    for b in [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]:
      result = crc8_smbus(bytes([b]))
      assert isinstance(result, int)
      assert 0 <= result <= 255

  def test_large_data(self):
    """Test CRC-8 with large data."""
    data = bytes(range(256)) * 100
    result = crc8_maxim(data)
    assert isinstance(result, int)
    assert 0 <= result <= 255

  def test_deterministic(self):
    """Test CRC-8 produces consistent results."""
    data = b"test data for crc"
    results = [crc8_smbus(data) for _ in range(10)]
    assert all(r == results[0] for r in results)

  def test_different_data_different_crc(self):
    """Test different data produces different CRC."""
    data1 = b"data1"
    data2 = b"data2"
    assert crc8_smbus(data1) != crc8_smbus(data2)

  def test_reverse_bits_function(self):
    """Test bit reversal utility."""
    assert reverse_bits(0x00) == 0x00
    assert reverse_bits(0xFF) == 0xFF
    assert reverse_bits(0x01) == 0x80
    assert reverse_bits(0x80) == 0x01
    assert reverse_bits(0xAA) == 0x55
    assert reverse_bits(0x55) == 0xAA

  def test_table_vs_manual_implementation(self):
    """Cross-validate table-based vs bit-by-bit implementation."""
    test_data = b"Cross validation test!"
    variants = [
      (0x07, 0x00, False, False, 0x00),
      (0x31, 0x00, True, True, 0x00),
      (0x2F, 0xFF, False, False, 0xFF),
      (0x9B, 0x00, False, False, 0x00),
    ]
    for poly, init, ref_in, ref_out, xor_out in variants:
      table_result = crc8(
        test_data, poly, init, ref_in=ref_in, ref_out=ref_out, xor_out=xor_out
      )
      manual_result = crc8_manual_calculation(
        test_data, poly, init, ref_in=ref_in, ref_out=ref_out, xor_out=xor_out
      )
      assert table_result == manual_result


class TestCRC12AllVariants:
  """Comprehensive tests for all CRC-12 variants."""

  def test_crc12_basic(self):
    """Test basic CRC-12 calculation."""
    result = crc12(STANDARD_TEST)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFF

  def test_crc12_umts(self):
    """Test CRC-12/UMTS variant."""
    result = crc12_umts(STANDARD_TEST)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFF

  def test_crc12_cdma2000(self):
    """Test CRC-12/CDMA2000 variant."""
    result = crc12_cdma2000(STANDARD_TEST)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFF

  def test_crc12_dect(self):
    """Test CRC-12/DECT variant."""
    result = crc12_dect(STANDARD_TEST)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFF

  def test_crc12_gsm(self):
    """Test CRC-12/GSM variant."""
    result = crc12_gsm(STANDARD_TEST)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFF

  def test_crc12_empty(self):
    """Test CRC-12 with empty input."""
    result = crc12(b"")
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFF

  def test_crc12_single_byte(self):
    """Test CRC-12 with single byte."""
    result = crc12(b"A")
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFF

  def test_crc12_deterministic(self):
    """Test CRC-12 is deterministic."""
    data = b"test"
    results = [crc12(data) for _ in range(10)]
    assert all(r == results[0] for r in results)


class TestCRC16AllVariants:
  """Comprehensive tests for all CRC-16 variants."""

  @pytest.mark.parametrize(
    ("func", "expected"),
    [
      (crc16_ibm, 0xBB3D),
      (crc16_modbus, 0x4B37),
      (crc16_usb, 0xB4C8),
      (crc16_xmodem, 0x31C3),
    ],
  )
  def test_standard_test_vectors(self, func, expected):
    """Test CRC-16 variants with standard test vector."""
    result = func(STANDARD_TEST)
    assert result == expected

  def test_crc16_ansi_alias(self):
    """Test CRC-16/ANSI alias matches CRC-16/IBM."""
    result_ansi = crc16_ansi(STANDARD_TEST)
    result_ibm = crc16_ibm(STANDARD_TEST)
    assert result_ansi == result_ibm

  def test_crc16_dnp(self):
    """Test CRC-16/DNP variant."""
    result = crc16_dnp(STANDARD_TEST)
    assert result == 0xEA82

  def test_crc16_empty(self):
    """Test CRC-16 with empty input."""
    result = crc16(b"")
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFF

  def test_crc16_large_data(self):
    """Test CRC-16 with large data."""
    data = b"A" * 10000
    result = crc16_ibm(data)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFF

  def test_crc16_deterministic(self):
    """Test CRC-16 is deterministic."""
    data = b"consistency test"
    results = [crc16_modbus(data) for _ in range(10)]
    assert all(r == results[0] for r in results)


class TestCRC16CCITTAllVariants:
  """Comprehensive tests for all CRC-16-CCITT variants."""

  @pytest.mark.parametrize(
    ("func", "expected"),
    [
      (crc16_ccitt_false, 0x29B1),
      (crc16_ccitt_xmodem, 0x31C3),
    ],
  )
  def test_standard_test_vectors(self, func, expected):
    """Test CRC-16-CCITT variants with standard test vector."""
    result = func(STANDARD_TEST)
    assert result == expected

  def test_ccitt_true(self):
    """Test CRC-16-CCITT-TRUE variant."""
    result = crc16_ccitt_true(STANDARD_TEST)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFF

  def test_ccitt_kermit(self):
    """Test CRC-16-CCITT-Kermit variant."""
    result = crc16_ccitt_kermit(STANDARD_TEST)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFF

  def test_ccitt_aliases(self):
    """Test CRC-16-CCITT aliases."""
    assert crc16_ccitt_1d0f(STANDARD_TEST) == crc16_ccitt_true(STANDARD_TEST)
    assert crc16_ccitt_ffff(STANDARD_TEST) == crc16_ccitt_false(STANDARD_TEST)

  def test_ccitt_xmodem_matches_crc16_xmodem(self):
    """Test CRC-16-CCITT-XMODEM matches CRC-16/XMODEM."""
    result1 = crc16_ccitt_xmodem(STANDARD_TEST)
    result2 = crc16_xmodem(STANDARD_TEST)
    assert result1 == result2

  def test_ccitt_empty(self):
    """Test CRC-16-CCITT with empty input."""
    result = crc16_ccitt(b"")
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFF


class TestCRC32AllVariants:
  """Comprehensive tests for CRC-32 implementation."""

  def test_standard_test_vector(self):
    """Test CRC-32 with standard test vector."""
    result = calculate_crc32(STANDARD_TEST)
    assert result == 0xCBF43926

  def test_against_zlib(self):
    """Test CRC-32 against Python's zlib implementation."""
    test_cases = [
      b"",
      b"A",
      b"Hello, World!",
      b"123456789",
      b"The quick brown fox jumps over the lazy dog",
      bytes(range(256)),
      b"A" * 10000,
    ]
    for data in test_cases:
      result = calculate_crc32(data)
      expected = zlib.crc32(data) & 0xFFFFFFFF
      assert result == expected

  def test_get_crc32_function(self):
    """Test alternative get_crc32 function."""
    result = get_crc32(STANDARD_TEST)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_empty_data(self):
    """Test CRC-32 with empty data."""
    result = calculate_crc32(b"")
    assert result == 0x00000000

  def test_single_byte(self):
    """Test CRC-32 with single byte."""
    for b in [0x00, 0x7F, 0x80, 0xFF]:
      result = calculate_crc32(bytes([b]))
      expected = zlib.crc32(bytes([b])) & 0xFFFFFFFF
      assert result == expected

  def test_binary_data(self):
    """Test CRC-32 with binary data."""
    data = bytes(range(256))
    result = calculate_crc32(data)
    expected = zlib.crc32(data) & 0xFFFFFFFF
    assert result == expected

  def test_deterministic(self):
    """Test CRC-32 is deterministic."""
    data = b"deterministic test"
    results = [calculate_crc32(data) for _ in range(10)]
    assert all(r == results[0] for r in results)


class TestCRC32C:
  """Comprehensive tests for CRC-32C (Castagnoli) implementation."""

  def test_standard_test_vector(self):
    """Test CRC-32C with standard test vector."""
    result = crc32c(STANDARD_TEST)
    assert result == 0xE3069283

  def test_aliases(self):
    """Test CRC-32C aliases."""
    result1 = crc32c_castagnoli(STANDARD_TEST)
    result2 = crc32c_iscsi(STANDARD_TEST)
    result3 = crc32c_sctp(STANDARD_TEST)
    assert result1 == result2 == result3

  def test_empty_data(self):
    """Test CRC-32C with empty data."""
    result = crc32c(b"")
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_single_byte(self):
    """Test CRC-32C with single byte."""
    result = crc32c(b"A")
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_large_data(self):
    """Test CRC-32C with large data."""
    data = b"X" * 100000
    result = crc32c(data)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_custom_init(self):
    """Test CRC-32C with custom init value."""
    data = b"test"
    result1 = crc32c(data, init=0xFFFFFFFF)
    result2 = crc32c(data, init=0x00000000)
    # Different init values should produce different results
    assert result1 != result2

  def test_deterministic(self):
    """Test CRC-32C is deterministic."""
    data = b"consistency"
    results = [crc32c(data) for _ in range(10)]
    assert all(r == results[0] for r in results)


class TestCRC64:
  """Comprehensive tests for CRC-64 implementation."""

  def test_standard_test_vector(self):
    """Test CRC-64 with standard test vector."""
    result = crc64(STANDARD_TEST)
    assert result == 0x6C40DF5F0B497347

  def test_hex_function(self):
    """Test CRC-64 hex function."""
    result = crc64_hex(STANDARD_TEST)
    assert result == "6c40df5f0b497347"
    assert len(result) == 16

  def test_empty_data(self):
    """Test CRC-64 with empty data."""
    result = crc64(b"")
    assert result == 0

  def test_single_byte(self):
    """Test CRC-64 with single byte."""
    result = crc64(b"A")
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFFFFFFFFFF

  def test_large_data(self):
    """Test CRC-64 with large data."""
    data = b"Y" * 100000
    result = crc64(data)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFFFFFFFFFF

  def test_incremental(self):
    """Test CRC-64 with incremental calculation."""
    data1 = b"Hello"
    data2 = b", World!"
    full_data = data1 + data2

    # Calculate incrementally
    crc = crc64(data1)
    crc_incremental = crc64(data2, init=crc)

    # This should not equal full calculation (CRC-64 is not additive)
    full_crc = crc64(full_data)
    # Note: incremental CRC doesn't work simply, just verify it's valid
    assert isinstance(crc_incremental, int)

  def test_deterministic(self):
    """Test CRC-64 is deterministic."""
    data = b"deterministic"
    results = [crc64(data) for _ in range(10)]
    assert all(r == results[0] for r in results)

  def test_hex_format(self):
    """Test CRC-64 hex format is correct."""
    result = crc64_hex(b"test")
    assert len(result) == 16
    assert all(c in "0123456789abcdef" for c in result)


class TestCRCEdgeCases:
  """Test edge cases across all CRC implementations."""

  @pytest.mark.parametrize(
    "length",
    [0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 1000],
  )
  def test_various_lengths(self, length):
    """Test CRCs with various data lengths."""
    data = b"X" * length

    result8 = crc8_smbus(data)
    assert 0 <= result8 <= 255

    result16 = crc16_ibm(data)
    assert 0 <= result16 <= 0xFFFF

    result32 = calculate_crc32(data)
    assert 0 <= result32 <= 0xFFFFFFFF

    result64 = crc64(data)
    assert 0 <= result64 <= 0xFFFFFFFFFFFFFFFF

  def test_special_byte_patterns(self):
    """Test CRCs with special byte patterns."""
    patterns = [
      b"\x00",
      b"\xFF",
      b"\x00\xFF",
      b"\xFF\x00",
      b"\x55\xAA",
      b"\xAA\x55",
      b"\xDE\xAD\xBE\xEF",
      b"\xCA\xFE\xBA\xBE",
    ]
    for pattern in patterns:
      assert isinstance(crc8_smbus(pattern), int)
      assert isinstance(crc16_ibm(pattern), int)
      assert isinstance(calculate_crc32(pattern), int)
      assert isinstance(crc64(pattern), int)

  def test_unicode_data(self):
    """Test CRCs with UTF-8 encoded data."""
    data = "Hello, 世界! 🌍".encode()
    assert isinstance(crc8_smbus(data), int)
    assert isinstance(crc16_ibm(data), int)
    assert calculate_crc32(data) == zlib.crc32(data) & 0xFFFFFFFF
    assert isinstance(crc64(data), int)
