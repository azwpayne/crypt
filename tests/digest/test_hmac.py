"""Tests for HMAC implementations.

Test vectors from RFC 2104 and additional edge cases.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

import pytest

from crypt.digest.HMAC.hmac_md5 import hmac_md5, hmac_md5_hex
from crypt.digest.HMAC.hmac_sha1 import hmac_sha1, hmac_sha1_hex
from crypt.digest.HMAC.hmac_sha256 import hmac_sha256, hmac_sha256_hex

if TYPE_CHECKING:
  from collections.abc import Callable


# RFC 2104 test vectors for MD5
# These are the official test vectors from the RFC
RFC2104_MD5_TEST_VECTORS: list[tuple[bytes, bytes, str]] = [
    # Test case 1: key = 16 bytes of 0x0b, data = "Hi There"
    (
        b"\x0b" * 16,
        b"Hi There",
        "9294727a3638bb1c13f48ef8158bfc9d",
    ),
    # Test case 2: key = "Jefe", data = "what do ya want for nothing?"
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "750c783e6ab0b503eaa86e310a5db738",
    ),
    # Test case 3: key = 16 bytes of 0xAA, data = 50 bytes of 0xDD
    (
        b"\xaa" * 16,
        b"\xdd" * 50,
        "56be34521d144c88dbb8c733f0e8b3f6",
    ),
    # Test case 4: key = 25 bytes (0x01-0x19), data = 50 bytes of 0xCD
    (
        bytes(range(1, 26)),
        b"\xcd" * 50,
        "697eaf0aca3a3aea3a75164746ffaa79",
    ),
    # Test case 5: key = 16 bytes of 0x0c, data = "Test With Truncation"
    (
        b"\x0c" * 16,
        b"Test With Truncation",
        "56461ef2342edc00f9bab995690efd4c",
    ),
    # Test case 6: key = 80 bytes of 0xAA, data = "Test Using Larger Than Block-Size Key - Hash Key First"
    (
        b"\xaa" * 80,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
    ),
    # Test case 7: key = 80 bytes of 0xAA, data = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    (
        b"\xaa" * 80,
        b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
        "6f630fad67cda0ee1fb1f562db3aa53e",
    ),
]


# RFC 2104 test vectors for SHA1 (from RFC 2202)
RFC2202_SHA1_TEST_VECTORS: list[tuple[bytes, bytes, str]] = [
    # Test case 1
    (
        b"\x0b" * 20,
        b"Hi There",
        "b617318655057264e28bc0b6fb378c8ef146be00",
    ),
    # Test case 2
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
    ),
    # Test case 3
    (
        b"\xaa" * 20,
        b"\xdd" * 50,
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    ),
    # Test case 4
    (
        bytes(range(1, 26)),
        b"\xcd" * 50,
        "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    ),
    # Test case 5
    (
        b"\x0c" * 20,
        b"Test With Truncation",
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
    ),
    # Test case 6
    (
        b"\xaa" * 80,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "aa4ae5e15272d00e95705637ce8a3b55ed402112",
    ),
    # Test case 7
    (
        b"\xaa" * 80,
        b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
        "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
    ),
]


# Test vectors for SHA256 (verified against Python's hmac module)
HMAC_SHA256_TEST_VECTORS: list[tuple[bytes, bytes, str]] = [
    # Test case 1
    (
        b"\x0b" * 32,
        b"Hi There",
        "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7",
    ),
    # Test case 2
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ),
    # Test case 3
    (
        b"\xaa" * 32,
        b"\xdd" * 50,
        "cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0",
    ),
    # Test case 4
    (
        bytes(range(1, 26)),
        b"\xcd" * 50,
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    ),
    # Test case 5
    (
        b"\x0c" * 32,
        b"Test With Truncation",
        "7546af01841fc09b1ab9c3749a5f1c17d4f589668a587b2700a9c97c1193cf42",
    ),
    # Test case 6
    (
        b"\xaa" * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    ),
    # Test case 7
    (
        b"\xaa" * 131,
        b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    ),
]


class TestHmacMD5:
    """Tests for HMAC-MD5 implementation."""

    @pytest.mark.parametrize(("key", "data", "expected"), RFC2104_MD5_TEST_VECTORS)
    def test_rfc2104_vectors(self, key: bytes, data: bytes, expected: str) -> None:
        """Test against RFC 2104 official test vectors."""
        result = hmac_md5(key, data).hex()
        assert result == expected

    def test_against_python_hmac(self) -> None:
        """Verify our implementation matches Python's hmac module."""
        test_cases = [
            (b"key", b"data"),
            (b"secret", b"message"),
            (b"\x00" * 16, b""),
            (b"long_key" * 20, b"some data here"),
        ]
        for key, data in test_cases:
            expected = hmac.new(key, data, hashlib.md5).digest()
            result = hmac_md5(key, data)
            assert result == expected

    def test_hex_function(self) -> None:
        """Test the hex convenience function."""
        key = b"test_key"
        data = b"test_data"
        result_hex = hmac_md5_hex(key, data)
        result_bytes = hmac_md5(key, data).hex()
        assert result_hex == result_bytes

    def test_empty_data(self) -> None:
        """Test HMAC with empty data."""
        key = b"key"
        expected = hmac.new(key, b"", hashlib.md5).digest()
        result = hmac_md5(key, b"")
        assert result == expected

    def test_empty_key(self) -> None:
        """Test HMAC with empty key."""
        key = b""
        data = b"data"
        expected = hmac.new(key, data, hashlib.md5).digest()
        result = hmac_md5(key, data)
        assert result == expected


class TestHmacSHA1:
    """Tests for HMAC-SHA1 implementation."""

    @pytest.mark.parametrize(("key", "data", "expected"), RFC2202_SHA1_TEST_VECTORS)
    def test_rfc2202_vectors(self, key: bytes, data: bytes, expected: str) -> None:
        """Test against RFC 2202 official test vectors."""
        result = hmac_sha1(key, data).hex()
        assert result == expected

    def test_against_python_hmac(self) -> None:
        """Verify our implementation matches Python's hmac module."""
        test_cases = [
            (b"key", b"data"),
            (b"secret", b"message"),
            (b"\x00" * 20, b""),
            (b"long_key" * 20, b"some data here"),
        ]
        for key, data in test_cases:
            expected = hmac.new(key, data, hashlib.sha1).digest()
            result = hmac_sha1(key, data)
            assert result == expected

    def test_hex_function(self) -> None:
        """Test the hex convenience function."""
        key = b"test_key"
        data = b"test_data"
        result_hex = hmac_sha1_hex(key, data)
        result_bytes = hmac_sha1(key, data).hex()
        assert result_hex == result_bytes

    def test_empty_data(self) -> None:
        """Test HMAC with empty data."""
        key = b"key"
        expected = hmac.new(key, b"", hashlib.sha1).digest()
        result = hmac_sha1(key, b"")
        assert result == expected

    def test_empty_key(self) -> None:
        """Test HMAC with empty key."""
        key = b""
        data = b"data"
        expected = hmac.new(key, data, hashlib.sha1).digest()
        result = hmac_sha1(key, data)
        assert result == expected


class TestHmacSHA256:
    """Tests for HMAC-SHA256 implementation."""

    @pytest.mark.parametrize(("key", "data", "expected"), HMAC_SHA256_TEST_VECTORS)
    def test_hmac_sha256_vectors(self, key: bytes, data: bytes, expected: str) -> None:
        """Test against verified HMAC-SHA256 test vectors."""
        result = hmac_sha256(key, data).hex()
        assert result == expected

    def test_against_python_hmac(self) -> None:
        """Verify our implementation matches Python's hmac module."""
        test_cases = [
            (b"key", b"data"),
            (b"secret", b"message"),
            (b"\x00" * 32, b""),
            (b"long_key" * 20, b"some data here"),
        ]
        for key, data in test_cases:
            expected = hmac.new(key, data, hashlib.sha256).digest()
            result = hmac_sha256(key, data)
            assert result == expected

    def test_hex_function(self) -> None:
        """Test the hex convenience function."""
        key = b"test_key"
        data = b"test_data"
        result_hex = hmac_sha256_hex(key, data)
        result_bytes = hmac_sha256(key, data).hex()
        assert result_hex == result_bytes

    def test_empty_data(self) -> None:
        """Test HMAC with empty data."""
        key = b"key"
        expected = hmac.new(key, b"", hashlib.sha256).digest()
        result = hmac_sha256(key, b"")
        assert result == expected

    def test_empty_key(self) -> None:
        """Test HMAC with empty key."""
        key = b""
        data = b"data"
        expected = hmac.new(key, data, hashlib.sha256).digest()
        result = hmac_sha256(key, data)
        assert result == expected


class TestHmacEdgeCases:
    """Edge case tests for all HMAC implementations."""

    @pytest.mark.parametrize(
        "hmac_func,hash_func",
        [
            (hmac_md5, hashlib.md5),
            (hmac_sha1, hashlib.sha1),
            (hmac_sha256, hashlib.sha256),
        ],
    )
    def test_large_data(
        self,
        hmac_func: Callable[[bytes, bytes], bytes],
        hash_func: Callable,
    ) -> None:
        """Test HMAC with large data."""
        key = b"test_key"
        data = b"x" * 10000
        expected = hmac.new(key, data, hash_func).digest()
        result = hmac_func(key, data)
        assert result == expected

    @pytest.mark.parametrize(
        "hmac_func,hash_func",
        [
            (hmac_md5, hashlib.md5),
            (hmac_sha1, hashlib.sha1),
            (hmac_sha256, hashlib.sha256),
        ],
    )
    def test_binary_data(
        self,
        hmac_func: Callable[[bytes, bytes], bytes],
        hash_func: Callable,
    ) -> None:
        """Test HMAC with binary data containing all byte values."""
        key = bytes(range(256))
        data = bytes(range(255, -1, -1))
        expected = hmac.new(key, data, hash_func).digest()
        result = hmac_func(key, data)
        assert result == expected

    @pytest.mark.parametrize(
        "hmac_func,hash_func",
        [
            (hmac_md5, hashlib.md5),
            (hmac_sha1, hashlib.sha1),
            (hmac_sha256, hashlib.sha256),
        ],
    )
    def test_key_exactly_block_size(
        self,
        hmac_func: Callable[[bytes, bytes], bytes],
        hash_func: Callable,
    ) -> None:
        """Test HMAC with key exactly equal to block size (64 bytes)."""
        key = b"x" * 64
        data = b"test data"
        expected = hmac.new(key, data, hash_func).digest()
        result = hmac_func(key, data)
        assert result == expected

    @pytest.mark.parametrize(
        "hmac_func,hash_func",
        [
            (hmac_md5, hashlib.md5),
            (hmac_sha1, hashlib.sha1),
            (hmac_sha256, hashlib.sha256),
        ],
    )
    def test_key_one_byte_over_block_size(
        self,
        hmac_func: Callable[[bytes, bytes], bytes],
        hash_func: Callable,
    ) -> None:
        """Test HMAC with key one byte over block size (65 bytes)."""
        key = b"x" * 65
        data = b"test data"
        expected = hmac.new(key, data, hash_func).digest()
        result = hmac_func(key, data)
        assert result == expected

    @pytest.mark.parametrize(
        "hmac_func,hash_func",
        [
            (hmac_md5, hashlib.md5),
            (hmac_sha1, hashlib.sha1),
            (hmac_sha256, hashlib.sha256),
        ],
    )
    def test_key_hash_output_size(
        self,
        hmac_func: Callable[[bytes, bytes], bytes],
        hash_func: Callable,
    ) -> None:
        """Test HMAC with key equal to hash output size."""
        hash_len = hash_func().digest_size
        key = b"x" * hash_len
        data = b"test data"
        expected = hmac.new(key, data, hash_func).digest()
        result = hmac_func(key, data)
        assert result == expected
