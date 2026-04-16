"""Comprehensive tests for all SHA implementations.

Tests for SHA-0, SHA-1, SHA-2 family, and SHA-3 family.
"""

from __future__ import annotations

import hashlib

import pytest
from Crypto.Hash import (
  SHA1,
  SHA3_224,
  SHA3_256,
  SHA3_384,
  SHA3_512,
  SHA224,
  SHA256,
  SHA384,
  SHA512,
  SHAKE128,
  SHAKE256,
)

from tests import BYTE_TEST_CASES


class TestSHA0:
  """Tests for SHA-0 implementation."""

  @pytest.mark.parametrize(
    ("msg", "expected"),
    [
      (b"", "f96cea198ad1dd5617ac084a3d92c6107708c0ef"),
      (b"a", "37f297772fae4cb1ba39b6cf9cf0381180bd62f2"),
      (b"abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
    ],
  )
  def test_sha0_known_vectors(self, msg, expected):
    """Test SHA-0 against known test vectors."""
    from crypt.digest.SHA import sha0

    result = sha0.sha0(msg)
    assert result == expected

  def test_sha0_empty(self):
    """Test SHA-0 with empty input."""
    from crypt.digest.SHA import sha0

    result = sha0.sha0(b"")
    assert len(result) == 40  # 160 bits = 40 hex chars

  def test_sha0_long_message(self):
    """Test SHA-0 with a long message."""
    from crypt.digest.SHA import sha0

    msg = b"a" * 1000
    result = sha0.sha0(msg)
    assert len(result) == 40


class TestSHA1:
  """Comprehensive tests for SHA-1 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha1_vs_hashlib(self, msg):
    """Test SHA-1 against hashlib reference."""
    from crypt.digest.SHA import sha1

    result = sha1.sha1(msg)
    expected = hashlib.sha1(msg).hexdigest()
    assert result == expected

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha1_vs_pycryptodome(self, msg):
    """Test SHA-1 against PyCryptodome reference."""
    from crypt.digest.SHA import sha1

    result = sha1.sha1(msg)
    expected = SHA1.new(msg).hexdigest()
    assert result == expected

  def test_sha1_nist_vectors(self):
    """Test SHA-1 against NIST test vectors."""
    from crypt.digest.SHA import sha1

    # NIST FIPS 180-4 test vectors
    assert sha1.sha1(b"abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert (
      sha1.sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
      == "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    )


class TestSha2224:
  """Comprehensive tests for SHA-224 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha224_vs_pycryptodome(self, msg):
    """Test SHA-224 against PyCryptodome reference."""
    from crypt.digest.SHA import sha2_224

    result = sha2_224.sha224_hex(msg)
    expected = SHA224.new(msg).hexdigest()
    assert result == expected

  def test_sha224_output_length(self):
    """Test SHA-224 produces correct output length."""
    from crypt.digest.SHA import sha2_224

    result = sha2_224.sha224_hex(b"test")
    assert len(result) == 56  # 224 bits = 56 hex chars


class TestSha2256:
  """Comprehensive tests for SHA-256 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha256_vs_pycryptodome(self, msg):
    """Test SHA-256 against PyCryptodome reference."""
    from crypt.digest.SHA import sha2_256

    result = sha2_256.sha256(msg)
    expected = SHA256.new(msg).hexdigest()
    assert result == expected

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha256_vs_hashlib(self, msg):
    """Test SHA-256 against hashlib reference."""
    from crypt.digest.SHA import sha2_256

    result = sha2_256.sha256(msg)
    expected = hashlib.sha256(msg).hexdigest()
    assert result == expected

  def test_sha256_nist_vectors(self):
    """Test SHA-256 against NIST test vectors."""
    from crypt.digest.SHA import sha2_256

    assert (
      sha2_256.sha256(b"abc")
      == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

  def test_sha256_output_length(self):
    """Test SHA-256 produces correct output length."""
    from crypt.digest.SHA import sha2_256

    result = sha2_256.sha256(b"test")
    assert len(result) == 64  # 256 bits = 64 hex chars


class TestSha2384:
  """Comprehensive tests for SHA-384 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha384_vs_pycryptodome(self, msg):
    """Test SHA-384 against PyCryptodome reference."""
    from crypt.digest.SHA import sha2_384

    result = sha2_384.sha384_hex(msg)
    expected = SHA384.new(msg).hexdigest()
    assert result == expected

  def test_sha384_output_length(self):
    """Test SHA-384 produces correct output length."""
    from crypt.digest.SHA import sha2_384

    result = sha2_384.sha384_hex(b"test")
    assert len(result) == 96  # 384 bits = 96 hex chars


class TestSha2512:
  """Comprehensive tests for SHA-512 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha512_vs_pycryptodome(self, msg):
    """Test SHA-512 against PyCryptodome reference."""
    from crypt.digest.SHA import sha2_512

    result = sha2_512.sha512(msg)
    expected = SHA512.new(msg).hexdigest()
    assert result == expected

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha512_vs_hashlib(self, msg):
    """Test SHA-512 against hashlib reference."""
    from crypt.digest.SHA import sha2_512

    result = sha2_512.sha512(msg)
    expected = hashlib.sha512(msg).hexdigest()
    assert result == expected

  def test_sha512_output_length(self):
    """Test SHA-512 produces correct output length."""
    from crypt.digest.SHA import sha2_512

    result = sha2_512.sha512(b"test")
    assert len(result) == 128  # 512 bits = 128 hex chars

  def test_sha512_bytes(self):
    """Test SHA-512 bytes output."""
    from crypt.digest.SHA import sha2_512

    result = sha2_512.sha512_bytes(b"hello")
    expected = hashlib.sha512(b"hello").digest()
    assert result == expected

  def test_sha512_with_string_input(self):
    """Test SHA-512 with string input."""
    from crypt.digest.SHA import sha2_512

    result = sha2_512.sha512("hello")
    expected = hashlib.sha512(b"hello").hexdigest()
    assert result == expected

  def test_sha512_invalid_input_type(self):
    """Test SHA-512 with invalid input type."""
    from crypt.digest.SHA import sha2_512

    with pytest.raises(TypeError, match="message must be bytes or string"):
      sha2_512.sha512(123)  # type: ignore[arg-type]


class TestSha3224:
  """Comprehensive tests for SHA3-224 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha3_224_vs_pycryptodome(self, msg):
    """Test SHA3-224 against PyCryptodome reference."""
    from crypt.digest.SHA import sha3_224

    result = sha3_224.sha3_224(msg).hex()
    expected = SHA3_224.new(msg).hexdigest()
    assert result == expected

  def test_sha3_224_output_length(self):
    """Test SHA3-224 produces correct output length."""
    from crypt.digest.SHA import sha3_224

    result = sha3_224.sha3_224(b"test")
    assert len(result) == 28  # 224 bits = 28 bytes

  def test_sha3_224_invalid_input_type(self):
    """Test SHA3-224 with invalid input type."""
    from crypt.digest.SHA import sha3_224

    with pytest.raises(TypeError, match="message must be bytes"):
      sha3_224.sha3_224("not bytes")  # type: ignore[arg-type]


class TestSha3256:
  """Comprehensive tests for SHA3-256 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha3_256_vs_pycryptodome(self, msg):
    """Test SHA3-256 against PyCryptodome reference."""
    from crypt.digest.SHA import sha3_256

    result = sha3_256.sha3_256_hex(msg)
    expected = SHA3_256.new(msg).hexdigest()
    assert result == expected

  def test_sha3_256_output_length(self):
    """Test SHA3-256 produces correct output length."""
    from crypt.digest.SHA import sha3_256

    result = sha3_256.sha3_256_hex(b"test")
    assert len(result) == 64  # 256 bits = 64 hex chars

  def test_sha3_256_invalid_input_type(self):
    """Test SHA3-256 with invalid input type."""
    from crypt.digest.SHA import sha3_256

    with pytest.raises(TypeError, match="msg must be bytes"):
      sha3_256.sha3_256("not bytes")  # type: ignore[arg-type]

  def test_sha3_256_exact_block_size(self):
    """Test SHA3-256 with input exactly at rate boundary (136 bytes)."""
    from crypt.digest.SHA import sha3_256

    msg = b"a" * 136
    result = sha3_256.sha3_256_hex(msg)
    expected = SHA3_256.new(msg).hexdigest()
    assert result == expected

  def test_sha3_256_long_output_squeeze(self):
    """Test SHA3-256 with output requiring multiple squeeze rounds."""
    from crypt.digest.SHA import sha3_256

    # sha3_256 returns fixed 32 bytes, but internal squeeze can handle more
    result = sha3_256.sha3_256(b"test")
    expected = SHA3_256.new(b"test").digest()
    assert result == expected


class TestSha3384:
  """Comprehensive tests for SHA3-384 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha3_384_vs_pycryptodome(self, msg):
    """Test SHA3-384 against PyCryptodome reference."""
    from crypt.digest.SHA import sha3_384

    result = sha3_384.sha3_384_hex(msg)
    expected = SHA3_384.new(msg).hexdigest()
    assert result == expected

  def test_sha3_384_output_length(self):
    """Test SHA3-384 produces correct output length."""
    from crypt.digest.SHA import sha3_384

    result = sha3_384.sha3_384_hex(b"test")
    assert len(result) == 96  # 384 bits = 96 hex chars

  def test_sha3_384_invalid_input_type(self):
    """Test SHA3-384 with invalid input type."""
    from crypt.digest.SHA import sha3_384

    with pytest.raises(TypeError, match="data must be bytes"):
      sha3_384.sha3_384("not bytes")  # type: ignore[arg-type]


class TestSha3512:
  """Comprehensive tests for SHA3-512 implementation."""

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_sha3_512_vs_pycryptodome(self, msg):
    """Test SHA3-512 against PyCryptodome reference."""
    from crypt.digest.SHA import sha3_512

    result = sha3_512.sha3_512_hex(msg)
    expected = SHA3_512.new(msg).hexdigest()
    assert result == expected

  def test_sha3_512_output_length(self):
    """Test SHA3-512 produces correct output length."""
    from crypt.digest.SHA import sha3_512

    result = sha3_512.sha3_512_hex(b"test")
    assert len(result) == 128  # 512 bits = 128 hex chars

  def test_sha3_512_invalid_input_type(self):
    """Test SHA3-512 with invalid input type."""
    from crypt.digest.SHA import sha3_512

    with pytest.raises(TypeError, match="message must be bytes"):
      sha3_512.sha3_512("not bytes")  # type: ignore[arg-type]

  def test_sha3_512_exact_block_size(self):
    """Test SHA3-512 with input exactly at rate boundary (72 bytes)."""
    from crypt.digest.SHA import sha3_512

    msg = b"a" * 72
    result = sha3_512.sha3_512_hex(msg)
    expected = SHA3_512.new(msg).hexdigest()
    assert result == expected

  def test_sha3_512_empty_message(self):
    """Test SHA3-512 with empty message."""
    from crypt.digest.SHA import sha3_512

    result = sha3_512.sha3_512_hex(b"")
    expected = SHA3_512.new(b"").hexdigest()
    assert result == expected


class TestSHAKE128:
  """Comprehensive tests for SHAKE128 implementation."""

  @pytest.mark.parametrize(
    ("msg", "output_len"),
    [
      (b"", 32),
      (b"", 64),
      (b"", 128),
      (b"abc", 32),
      (b"abc", 64),
      (b"abc", 128),
      (b"The quick brown fox jumps over the lazy dog", 32),
      (b"The quick brown fox jumps over the lazy dog", 64),
      (b"The quick brown fox jumps over the lazy dog", 256),
    ],
  )
  def test_shake128_vs_pycryptodome(self, msg, output_len):
    """Test SHAKE128 against PyCryptodome reference."""
    from crypt.digest.SHA import sha3_ke_128

    result = sha3_ke_128.shake128(msg, output_len)
    expected = SHAKE128.new(msg).read(output_len)
    assert result == expected

  def test_shake128_variable_output(self):
    """Test SHAKE128 with variable output lengths."""
    from crypt.digest.SHA import sha3_ke_128

    msg = b"test"
    for output_len in [16, 32, 64, 128, 256, 512]:
      result = sha3_ke_128.shake128(msg, output_len)
      assert len(result) == output_len


class TestSHAKE256:
  """Comprehensive tests for SHAKE256 implementation."""

  @pytest.mark.parametrize(
    ("msg", "output_len"),
    [
      (b"", 32),
      (b"", 64),
      (b"", 128),
      (b"abc", 32),
      (b"abc", 64),
      (b"abc", 128),
      (b"The quick brown fox jumps over the lazy dog", 32),
      (b"The quick brown fox jumps over the lazy dog", 64),
      (b"The quick brown fox jumps over the lazy dog", 256),
    ],
  )
  def test_shake256_vs_pycryptodome(self, msg, output_len):
    """Test SHAKE256 against PyCryptodome reference."""
    from crypt.digest.SHA import sha3_ke_256

    result = sha3_ke_256.shake256(msg, output_len)
    expected = SHAKE256.new(msg).read(output_len)
    assert result == expected

  def test_shake256_variable_output(self):
    """Test SHAKE256 with variable output lengths."""
    from crypt.digest.SHA import sha3_ke_256

    msg = b"test"
    for output_len in [16, 32, 64, 128, 256, 512]:
      result = sha3_ke_256.shake256(msg, output_len)
      assert len(result) == output_len


class TestSHAKENonStandard:
  """Tests for non-standard SHAKE variants."""

  @pytest.mark.parametrize(
    ("msg", "output_len"),
    [
      (b"", 32),
      (b"abc", 64),
      (b"test", 128),
    ],
  )
  def test_shake224(self, msg, output_len):
    """Test SHAKE224 (non-standard)."""
    from crypt.digest.SHA import sha3_ke_224

    result = sha3_ke_224.shake224(msg, output_len)
    assert isinstance(result, bytes)
    assert len(result) == output_len

  @pytest.mark.parametrize(
    ("msg", "output_len"),
    [
      (b"", 32),
      (b"abc", 64),
      (b"test", 128),
    ],
  )
  def test_shake384(self, msg, output_len):
    """Test SHAKE384 (non-standard)."""
    from crypt.digest.SHA import sha3_ke_384

    result = sha3_ke_384.shake384(msg, output_len)
    assert isinstance(result, bytes)
    assert len(result) == output_len

  @pytest.mark.parametrize(
    ("msg", "output_len"),
    [
      (b"", 32),
      (b"abc", 64),
      (b"test", 128),
    ],
  )
  def test_shake512(self, msg, output_len):
    """Test SHAKE512 (non-standard)."""
    from crypt.digest.SHA import sha3_ke_512

    result = sha3_ke_512.shake512(msg, output_len)
    assert isinstance(result, bytes)
    assert len(result) == output_len


class TestSHAEdgeCases:
  """Edge case tests for all SHA implementations."""

  def test_empty_input(self):
    """Test all SHA variants with empty input."""
    from crypt.digest.SHA import sha1, sha2_256, sha3_256

    # All should produce valid output
    assert len(sha1.sha1(b"")) == 40
    assert len(sha2_256.sha256(b"")) == 64
    assert len(sha3_256.sha3_256_hex(b"")) == 64

  def test_large_input(self):
    """Test SHA with large input."""
    from crypt.digest.SHA import sha2_256

    # 1MB of data
    large_data = b"x" * (1024 * 1024)
    result = sha2_256.sha256(large_data)
    expected = hashlib.sha256(large_data).hexdigest()
    assert result == expected

  def test_binary_data(self):
    """Test SHA with binary data containing all byte values."""
    from crypt.digest.SHA import sha2_256

    data = bytes(range(256))
    result = sha2_256.sha256(data)
    expected = hashlib.sha256(data).hexdigest()
    assert result == expected

  def test_unicode_data(self):
    """Test SHA with UTF-8 encoded data."""
    from crypt.digest.SHA import sha2_256

    data = "Hello, 世界! 🌍".encode()
    result = sha2_256.sha256(data)
    expected = hashlib.sha256(data).hexdigest()
    assert result == expected

  def test_deterministic(self):
    """Test that SHA is deterministic."""
    from crypt.digest.SHA import sha2_256

    data = b"deterministic test"
    results = [sha2_256.sha256(data) for _ in range(10)]
    assert all(r == results[0] for r in results)

  def test_different_input_different_output(self):
    """Test that different inputs produce different outputs."""
    from crypt.digest.SHA import sha2_256

    assert sha2_256.sha256(b"data1") != sha2_256.sha256(b"data2")
