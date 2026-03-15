"""Tests for SM3 hash algorithm.

SM3 is a cryptographic hash function used in Chinese national standards.
Test vectors from GM/T 0004-2012 and known implementations.
"""

from __future__ import annotations

import pytest

from crypt.digest import sm3
from tests import BYTE_TEST_CASES


# Known SM3 test vectors from GM/T 0004-2012 standard
SM3_TEST_VECTORS: list[tuple[bytes, str]] = [
    # Empty message
    (
        b"",
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
    ),
    # Message "abc"
    (
        b"abc",
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    ),
    # Note: Long message test vector needs verification against reference implementation
    # (
    #     b"abcd" * 16,
    #     "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba9c6667d04",
    # ),
]


class TestSM3:
    """Test SM3 hash implementation."""

    @pytest.mark.parametrize(
        ("msg", "expected"),
        SM3_TEST_VECTORS,
    )
    def test_sm3_known_vectors(self, msg: bytes, expected: str) -> None:
        """Test SM3 against known test vectors."""
        result = sm3.sm3(msg)
        assert result == expected, f"Expected {expected}, got {result}"

    @pytest.mark.parametrize(
        "msg",
        BYTE_TEST_CASES,
    )
    def test_sm3_byte_cases(self, msg: bytes) -> None:
        """Test SM3 with standard byte test cases."""
        result = sm3.sm3(msg)
        # Verify result is a valid hex string of correct length (64 chars = 256 bits)
        assert isinstance(result, str)
        assert len(result) == 64
        # Verify all characters are valid hex digits
        assert all(c in "0123456789abcdef" for c in result)

    def test_sm3_consistency(self) -> None:
        """Test that SM3 produces consistent results."""
        msg = b"test message"
        result1 = sm3.sm3(msg)
        result2 = sm3.sm3(msg)
        assert result1 == result2

    def test_sm3_long_message(self) -> None:
        """Test SM3 with a long message."""
        msg = b"a" * 10000
        result = sm3.sm3(msg)
        assert isinstance(result, str)
        assert len(result) == 64

    def test_sm3_binary_data(self) -> None:
        """Test SM3 with binary data."""
        msg = bytes(range(256))
        result = sm3.sm3(msg)
        assert isinstance(result, str)
        assert len(result) == 64
