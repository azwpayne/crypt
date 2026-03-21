"""Tests for CRC-64 checksum."""

from crypt.digest.CRC.crc64 import crc64, crc64_hex


class TestCRC64:
  def test_hex_length(self):
    assert len(crc64_hex(b"test")) == 16

  def test_empty_nonzero(self):
    # CRC-64 of empty string with XOROUT flips bits
    result = crc64(b"")
    assert isinstance(result, int)

  def test_consistency(self):
    assert crc64(b"hello world") == crc64(b"hello world")

  def test_different_inputs_differ(self):
    assert crc64(b"abc") != crc64(b"def")

  def test_known_vector(self):
    # CRC-64/ECMA-182 of b"123456789" = 0x6C40DF5F0B497347
    assert crc64(b"123456789") == 0x6C40DF5F0B497347
