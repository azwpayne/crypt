# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_crc.py
# @time    : 2026/3/9 20:56 Mon
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for CRC algorithms
from crypt.digest.CRC import crc8

import pytest


class TestCRC8:
  """Test CRC-8 algorithm implementations."""

  # Standard test data used across CRC implementations
  TEST_DATA = b"123456789"

  def test_crc8_maxim(self):
    """Test CRC-8/MAXIM against known test vector from Maxim official documentation."""
    result = crc8.crc8_maxim(self.TEST_DATA)
    assert result == 0xA1, f"CRC-8/MAXIM test failed: expected 0xA1, got 0x{result:02X}"

  def test_crc8_autosar(self):
    """Test CRC-8/AUTOSAR against known test vector from AUTOSAR specification."""
    result = crc8.crc8_autosar(self.TEST_DATA)
    assert result == 0xDF, (
      f"CRC-8/AUTOSAR test failed: expected 0xDF, got 0x{result:02X}"
    )

  def test_crc8_lte(self):
    """Test CRC-8/LTE against known test vector from 3GPP specification."""
    result = crc8.crc8_lte(self.TEST_DATA)
    assert result == 0xEA, f"CRC-8/LTE test failed: expected 0xEA, got 0x{result:02X}"

  def test_crc8_smbus(self):
    """Test CRC-8/SMBUS against known test vector from SMBus specification."""
    result = crc8.crc8_smbus(self.TEST_DATA)
    assert result == 0xF4, f"CRC-8/SMBUS test failed: expected 0xF4, got 0x{result:02X}"

  def test_crc8_bluetooth(self):
    """Test CRC-8/BLUETOOTH against known test vector from Bluetooth specification."""
    result = crc8.crc8_bluetooth(self.TEST_DATA)
    assert result == 0x26, (
      f"CRC-8/BLUETOOTH test failed: expected 0x26, got 0x{result:02X}"
    )

  def test_crc8_j1850(self):
    """Test CRC-8/SAE-J1850 against known test vector from SAE J1850 specification."""
    result = crc8.crc8_j1850(self.TEST_DATA)
    assert result == 0x4B, (
      f"CRC-8/SAE-J1850 test failed: expected 0x4B, got 0x{result:02X}"
    )


class TestCRCPlaceholders:
  """Placeholder tests for CRC variants to be implemented."""

  @pytest.mark.skip(reason="Not yet implemented")
  def test_crc12(self):
    """Test CRC-12 implementation."""

  @pytest.mark.skip(reason="Not yet implemented")
  def test_crc16(self):
    """Test CRC-16 implementation."""

  @pytest.mark.skip(reason="Not yet implemented")
  def test_crc16_ccitt(self):
    """Test CRC-16/CCITT implementation."""

  @pytest.mark.skip(reason="Not yet implemented")
  def test_crc32(self):
    """Test CRC-32 implementation."""
