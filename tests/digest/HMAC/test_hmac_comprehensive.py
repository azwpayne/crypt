"""Comprehensive tests for HMAC module including CMAC.

Tests for HMAC-MD5, HMAC-SHA1, HMAC-SHA256, and CMAC implementations.
"""

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
from crypt.digest.HMAC.cmac import cmac, cmac_aes128, cmac_aes256
from crypt.digest.HMAC.hmac_md5 import hmac_md5, hmac_md5_hex
from crypt.digest.HMAC.hmac_sha1 import hmac_sha1, hmac_sha1_hex
from crypt.digest.HMAC.hmac_sha256 import hmac_sha256, hmac_sha256_hex

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import CMAC


class TestHMACVariousKeys:
  """Test HMAC with various key sizes and types."""

  @pytest.mark.parametrize(
    "key_size",
    [1, 8, 16, 32, 64, 65, 100, 128, 256],
  )
  def test_hmac_various_key_sizes_md5(self, key_size):
    """Test HMAC-MD5 with various key sizes."""
    key = bytes(range(key_size % 256)) * ((key_size // 256) + 1)
    key = key[:key_size]
    data = b"test data"

    result = hmac_md5(key, data)
    expected = stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert result == expected

  @pytest.mark.parametrize(
    "key_size",
    [1, 8, 16, 20, 32, 64, 65, 100, 128, 256],
  )
  def test_hmac_various_key_sizes_sha1(self, key_size):
    """Test HMAC-SHA1 with various key sizes."""
    key = bytes(range(key_size % 256)) * ((key_size // 256) + 1)
    key = key[:key_size]
    data = b"test data"

    result = hmac_sha1(key, data)
    expected = stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert result == expected

  @pytest.mark.parametrize(
    "key_size",
    [1, 8, 16, 32, 64, 65, 100, 128, 256],
  )
  def test_hmac_various_key_sizes_sha256(self, key_size):
    """Test HMAC-SHA256 with various key sizes."""
    key = bytes(range(key_size % 256)) * ((key_size // 256) + 1)
    key = key[:key_size]
    data = b"test data"

    result = hmac_sha256(key, data)
    expected = stdlib_hmac.new(key, data, hashlib.sha256).digest()
    assert result == expected


class TestHMACVariousDataSizes:
  """Test HMAC with various data sizes."""

  @pytest.mark.parametrize(
    "data_size",
    [0, 1, 16, 64, 100, 1000, 10000],
  )
  def test_hmac_various_data_sizes_md5(self, data_size):
    """Test HMAC-MD5 with various data sizes."""
    key = b"test_key"
    data = b"x" * data_size

    result = hmac_md5(key, data)
    expected = stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert result == expected

  @pytest.mark.parametrize(
    "data_size",
    [0, 1, 16, 64, 100, 1000, 10000],
  )
  def test_hmac_various_data_sizes_sha1(self, data_size):
    """Test HMAC-SHA1 with various data sizes."""
    key = b"test_key"
    data = b"x" * data_size

    result = hmac_sha1(key, data)
    expected = stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert result == expected

  @pytest.mark.parametrize(
    "data_size",
    [0, 1, 16, 64, 100, 1000, 10000],
  )
  def test_hmac_various_data_sizes_sha256(self, data_size):
    """Test HMAC-SHA256 with various data sizes."""
    key = b"test_key"
    data = b"x" * data_size

    result = hmac_sha256(key, data)
    expected = stdlib_hmac.new(key, data, hashlib.sha256).digest()
    assert result == expected


class TestHMACHexFunctions:
  """Test HMAC hex convenience functions."""

  def test_hmac_md5_hex(self):
    """Test HMAC-MD5 hex function."""
    key = b"key"
    data = b"data"
    result = hmac_md5_hex(key, data)
    assert isinstance(result, str)
    assert len(result) == 32  # 128 bits = 32 hex chars
    assert result == hmac_md5(key, data).hex()

  def test_hmac_sha1_hex(self):
    """Test HMAC-SHA1 hex function."""
    key = b"key"
    data = b"data"
    result = hmac_sha1_hex(key, data)
    assert isinstance(result, str)
    assert len(result) == 40  # 160 bits = 40 hex chars
    assert result == hmac_sha1(key, data).hex()

  def test_hmac_sha256_hex(self):
    """Test HMAC-SHA256 hex function."""
    key = b"key"
    data = b"data"
    result = hmac_sha256_hex(key, data)
    assert isinstance(result, str)
    assert len(result) == 64  # 256 bits = 64 hex chars
    assert result == hmac_sha256(key, data).hex()


class TestHMACSpecialCases:
  """Test HMAC with special input cases."""

  def test_empty_key(self):
    """Test HMAC with empty key."""
    key = b""
    data = b"data"
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()

  def test_empty_data(self):
    """Test HMAC with empty data."""
    key = b"key"
    data = b""
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()

  def test_both_empty(self):
    """Test HMAC with both empty key and data."""
    key = b""
    data = b""
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()

  def test_binary_key_and_data(self):
    """Test HMAC with binary data containing all byte values."""
    key = bytes(range(256))
    data = bytes(range(255, -1, -1))
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()

  def test_unicode_data(self):
    """Test HMAC with UTF-8 encoded Unicode data."""
    key = "密钥".encode()
    data = "Hello, 世界! 🌍".encode()
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()


class TestHMACDeterminism:
  """Test HMAC determinism."""

  def test_hmac_md5_deterministic(self):
    """Test HMAC-MD5 is deterministic."""
    key = b"test_key"
    data = b"test_data"
    results = [hmac_md5(key, data) for _ in range(10)]
    assert all(r == results[0] for r in results)

  def test_hmac_sha1_deterministic(self):
    """Test HMAC-SHA1 is deterministic."""
    key = b"test_key"
    data = b"test_data"
    results = [hmac_sha1(key, data) for _ in range(10)]
    assert all(r == results[0] for r in results)

  def test_hmac_sha256_deterministic(self):
    """Test HMAC-SHA256 is deterministic."""
    key = b"test_key"
    data = b"test_data"
    results = [hmac_sha256(key, data) for _ in range(10)]
    assert all(r == results[0] for r in results)


class TestCMAC:
  """Comprehensive tests for CMAC implementation."""

  @pytest.mark.parametrize(
    ("key", "data"),
    [
      (b"\x00" * 16, b""),
      (b"\x00" * 16, b"test"),
      (bytes(range(16)), b"Hello, World!"),
      (b"\xff" * 16, b"x" * 100),
    ],
  )
  def test_cmac_aes128_vs_pycryptodome(self, key, data):
    """Test CMAC-AES128 against PyCryptodome reference."""
    result = cmac_aes128(key, data)
    expected = CMAC.new(key, ciphermod=AES).update(data).digest()
    assert result == expected

  @pytest.mark.parametrize(
    ("key", "data"),
    [
      (b"\x00" * 32, b""),
      (b"\x00" * 32, b"test"),
      (bytes(range(32)), b"Hello, World!"),
      (b"\xff" * 32, b"x" * 100),
    ],
  )
  def test_cmac_aes256_vs_pycryptodome(self, key, data):
    """Test CMAC-AES256 against PyCryptodome reference."""
    result = cmac_aes256(key, data)
    expected = CMAC.new(key, ciphermod=AES).update(data).digest()
    assert result == expected

  def test_cmac_output_length(self):
    """Test CMAC output length."""
    key = b"\x00" * 16
    data = b"test"
    result = cmac_aes128(key, data)
    assert len(result) == 16  # AES block size

  def test_cmac_generic_function(self):
    """Test generic CMAC function."""
    key = b"\x00" * 16
    data = b"test"
    result = cmac(key, data)
    expected = cmac_aes128(key, data)
    assert result == expected

  def test_cmac_empty_data(self):
    """Test CMAC with empty data."""
    key = b"\x00" * 16
    data = b""
    result = cmac_aes128(key, data)
    expected = CMAC.new(key, ciphermod=AES).update(data).digest()
    assert result == expected

  def test_cmac_deterministic(self):
    """Test CMAC is deterministic."""
    key = b"\x00" * 16
    data = b"test_data"
    results = [cmac_aes128(key, data) for _ in range(10)]
    assert all(r == results[0] for r in results)

  def test_cmac_different_keys_different_output(self):
    """Test that different keys produce different outputs."""
    key1 = b"\x00" * 16
    key2 = b"\x01" * 16
    data = b"test"
    assert cmac_aes128(key1, data) != cmac_aes128(key2, data)

  def test_cmac_different_data_different_output(self):
    """Test that different data produces different outputs."""
    key = b"\x00" * 16
    data1 = b"data1"
    data2 = b"data2"
    assert cmac_aes128(key, data1) != cmac_aes128(key, data2)


class TestHMACBlockSizeBoundaries:
  """Test HMAC with keys at block size boundaries."""

  def test_key_exactly_block_size(self):
    """Test HMAC with key exactly equal to block size (64 bytes)."""
    key = b"x" * 64
    data = b"test"
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()

  def test_key_one_byte_less_than_block_size(self):
    """Test HMAC with key one byte less than block size (63 bytes)."""
    key = b"x" * 63
    data = b"test"
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()

  def test_key_one_byte_more_than_block_size(self):
    """Test HMAC with key one byte more than block size (65 bytes)."""
    key = b"x" * 65
    data = b"test"
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()

  def test_key_double_block_size(self):
    """Test HMAC with key twice the block size (128 bytes)."""
    key = b"x" * 128
    data = b"test"
    assert hmac_md5(key, data) == stdlib_hmac.new(key, data, hashlib.md5).digest()
    assert hmac_sha1(key, data) == stdlib_hmac.new(key, data, hashlib.sha1).digest()
    assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()
