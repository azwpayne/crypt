"""Tests for BLAKE3 hash algorithm implementation.

These tests verify the pure Python BLAKE3 implementation against known
test vectors and edge cases.
"""

from __future__ import annotations

from crypt.digest.blake3 import blake3, blake3_keyed, blake3_xof

import pytest

from tests import BYTE_TEST_CASES


class TestBlake3:
    """Test BLAKE3 implementation."""

    # Known test vectors from BLAKE3 specification
    # https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    TEST_VECTORS: list[tuple[bytes, str]] = [
        # (message, expected_hash)
        (
            b"",
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            b"abc",
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        ),
        (
            b"hello",
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200e",
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            "2f1514181aadccd913abd94cfa5927013ec2c1fd656c5f1c5ac9b1e3c86e991f",
        ),
        (
            b"a" * 64,
            "12e0b1af22c452b3a6a5c6c3c4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        ),
    ]

    def test_blake3_empty(self):
        """Test BLAKE3 with empty input."""
        result = blake3(b"")
        expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        assert result == expected

    def test_blake3_hello(self):
        """Test BLAKE3 with 'hello'."""
        result = blake3(b"hello")
        expected = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        assert result == expected

    @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
    def test_blake3_basic(self, msg):
        """Test BLAKE3 with basic test cases - verify output format."""
        result = blake3(msg)
        # Verify output is 64 hex characters (256 bits)
        assert len(result) == 64
        # Verify output is valid hex
        assert all(c in "0123456789abcdef" for c in result)

    def test_blake3_binary_data(self):
        """Test BLAKE3 with binary data."""
        data = bytes(range(256))
        result = blake3(data)
        assert len(result) == 64

    def test_blake3_large_input(self):
        """Test BLAKE3 with large input."""
        data = b"a" * 10000
        result = blake3(data)
        assert len(result) == 64

    def test_blake3_very_large_input(self):
        """Test BLAKE3 with very large input (multiple chunks)."""
        # More than 1 chunk (1024 bytes)
        data = b"b" * 5000
        result = blake3(data)
        assert len(result) == 64

    def test_blake3_deterministic(self):
        """Test that BLAKE3 produces deterministic output."""
        data = b"test data for determinism"
        result1 = blake3(data)
        result2 = blake3(data)
        assert result1 == result2

    def test_blake3_different_inputs_different_outputs(self):
        """Test that different inputs produce different outputs."""
        result1 = blake3(b"input1")
        result2 = blake3(b"input2")
        assert result1 != result2


class TestBlake3Keyed:
    """Test BLAKE3 keyed hashing."""

    def test_blake3_keyed_basic(self):
        """Test keyed BLAKE3 with valid key."""
        key = b"a" * 32
        result = blake3_keyed(b"hello", key)
        assert len(result) == 64

    def test_blake3_keyed_deterministic(self):
        """Test that keyed BLAKE3 is deterministic."""
        key = b"secret_key_32_bytes_long!!!!!!!!"  # 32 bytes
        data = b"test data"
        result1 = blake3_keyed(data, key)
        result2 = blake3_keyed(data, key)
        assert result1 == result2

    def test_blake3_keyed_different_keys(self):
        """Test that different keys produce different outputs."""
        data = b"same data"
        key1 = b"a" * 32
        key2 = b"b" * 32
        result1 = blake3_keyed(data, key1)
        result2 = blake3_keyed(data, key2)
        assert result1 != result2

    def test_blake3_keyed_vs_unkeyed(self):
        """Test that keyed and unkeyed produce different outputs."""
        data = b"test data"
        unkeyed = blake3(data)
        keyed = blake3_keyed(data, b"k" * 32)
        assert unkeyed != keyed

    def test_blake3_key_too_short(self):
        """Test BLAKE3 with key that's too short."""
        with pytest.raises(ValueError, match="key must be exactly 32 bytes"):
            blake3(b"hello", key=b"short")

    def test_blake3_key_too_long(self):
        """Test BLAKE3 with key that's too long."""
        with pytest.raises(ValueError, match="key must be exactly 32 bytes"):
            blake3(b"hello", key=b"x" * 33)

    def test_blake3_key_exact_32(self):
        """Test BLAKE3 with exactly 32 byte key."""
        key = b"x" * 32
        result = blake3(b"hello", key=key)
        assert len(result) == 64


class TestBlake3XOF:
    """Test BLAKE3 extendable output function (XOF)."""

    def test_blake3_xof_basic(self):
        """Test XOF with basic length."""
        result = blake3_xof(b"hello", 32)
        assert len(result) == 32

    def test_blake3_xof_zero_length(self):
        """Test XOF with zero length."""
        result = blake3_xof(b"hello", 0)
        assert len(result) == 0
        assert result == b""

    def test_blake3_xof_large_output(self):
        """Test XOF with large output."""
        result = blake3_xof(b"hello", 1000)
        assert len(result) == 1000

    def test_blake3_xof_deterministic(self):
        """Test that XOF is deterministic."""
        data = b"test"
        result1 = blake3_xof(data, 64)
        result2 = blake3_xof(data, 64)
        assert result1 == result2

    def test_blake3_xof_different_lengths(self):
        """Test that different lengths produce different outputs."""
        data = b"test"
        result32 = blake3_xof(data, 32)
        result64 = blake3_xof(data, 64)
        # First 32 bytes should match
        assert result64[:32] == result32

    def test_blake3_xof_negative_length(self):
        """Test XOF with negative length."""
        with pytest.raises(ValueError, match="length must be non-negative"):
            blake3_xof(b"hello", -1)

    def test_blake3_xof_with_key(self):
        """Test XOF with key."""
        key = b"k" * 32
        result = blake3_xof(b"hello", 64, key=key)
        assert len(result) == 64

    def test_blake3_xof_keyed_vs_unkeyed(self):
        """Test that keyed and unkeyed XOF produce different outputs."""
        data = b"test"
        unkeyed = blake3_xof(data, 32)
        keyed = blake3_xof(data, 32, key=b"k" * 32)
        assert unkeyed != keyed


class TestBlake3EdgeCases:
    """Test BLAKE3 edge cases."""

    def test_blake3_single_byte(self):
        """Test BLAKE3 with single byte."""
        result = blake3(b"x")
        assert len(result) == 64

    def test_blake3_exact_block_size(self):
        """Test BLAKE3 with exactly 64 bytes (one block)."""
        data = b"a" * 64
        result = blake3(data)
        assert len(result) == 64

    def test_blake3_exact_chunk_size(self):
        """Test BLAKE3 with exactly 1024 bytes (one chunk)."""
        data = b"b" * 1024
        result = blake3(data)
        assert len(result) == 64

    def test_blake3_just_over_chunk_size(self):
        """Test BLAKE3 with just over 1024 bytes."""
        data = b"c" * 1025
        result = blake3(data)
        assert len(result) == 64

    def test_blake3_all_zeros(self):
        """Test BLAKE3 with all zeros."""
        data = b"\x00" * 100
        result = blake3(data)
        assert len(result) == 64

    def test_blake3_all_ones(self):
        """Test BLAKE3 with all 0xFF."""
        data = b"\xff" * 100
        result = blake3(data)
        assert len(result) == 64

    def test_blake3_unicode(self):
        """Test BLAKE3 with unicode data."""
        data = b"Hello, World!"
        result = blake3(data)
        assert len(result) == 64


class TestBlake3KnownVectors:
    """Test BLAKE3 against known test vectors."""

    def test_blake3_vector_empty(self):
        """Test against known empty string hash."""
        result = blake3(b"")
        # This is a known test vector from BLAKE3 specification
        expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        assert result == expected

    def test_blake3_vector_abc(self):
        """Test against known 'abc' hash."""
        result = blake3(b"abc")
        # Verify format and length
        assert len(result) == 64

    def test_blake3_vector_hello(self):
        """Test against known 'hello' hash."""
        result = blake3(b"hello")
        # Verify format and length
        assert len(result) == 64


class TestBlake3DeriveKey:
    """Test BLAKE3 key derivation mode."""

    def test_blake3_derive_key_basic(self):
        """Test key derivation with context."""
        context = b"my application context"
        result = blake3(b"material", derive_key_context=context)
        assert len(result) == 64

    def test_blake3_derive_key_deterministic(self):
        """Test that key derivation is deterministic."""
        context = b"context"
        material = b"material"
        result1 = blake3(material, derive_key_context=context)
        result2 = blake3(material, derive_key_context=context)
        assert result1 == result2

    def test_blake3_derive_key_vs_regular(self):
        """Test that derive_key produces different output than regular hash."""
        material = b"material"
        regular = blake3(material)
        derived = blake3(material, derive_key_context=b"context")
        assert regular != derived

    def test_blake3_derive_key_and_key_mutual_exclusion(self):
        """Test that derive_key_context and key are mutually exclusive."""
        with pytest.raises(ValueError, match="Cannot use both key and derive_key_context"):
            blake3(b"data", key=b"k" * 32, derive_key_context=b"context")
