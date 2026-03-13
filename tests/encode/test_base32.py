# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base32.py
# @time    : 2026/3/13
# @desc    : Tests for base32 encoding/decoding
import base64

import pytest

from crypt.encode import base32
from tests import BYTE_TEST_CASES


@pytest.mark.parametrize("msg", BYTE_TEST_CASES)
class TestBase32:
    """Test base32 encoding and decoding against Python standard library."""

    def test_base32_encode(self, msg):
        """Verify base32_encode matches standard library output."""
        result = base32.base32_encode(msg)
        expected = base64.b32encode(msg).decode("ascii")
        assert result == expected, f"Encoding failed for: {msg!r}"

    def test_base32_decode(self, msg):
        """Verify base32_decode correctly decodes encoded data."""
        encoded = base32.base32_encode(msg)
        decoded = base32.base32_decode(encoded)
        assert decoded == msg, f"Decoding failed for: {msg!r}"

    def test_base32_roundtrip(self, msg):
        """Verify encode/decode roundtrip."""
        encoded = base32.base32_encode(msg)
        decoded = base32.base32_decode(encoded)
        assert decoded == msg, f"Roundtrip failed for: {msg!r}"


class TestBase32EdgeCases:
    """Test edge cases and error handling."""

    def test_base32_empty(self):
        """Test empty input."""
        assert base32.base32_encode(b"") == ""
        assert base32.base32_decode("") == b""

    def test_base32_invalid_char(self):
        """Test decoding with invalid characters."""
        with pytest.raises(ValueError, match="Invalid Base32 character"):
            base32.base32_decode("A!BC")

    def test_base32_binary_data(self):
        """Test with various binary data patterns."""
        test_cases = [
            b"\x00" * 10,
            b"\xff" * 10,
            b"\x00\x01\x02\x03\x04\x05",
            bytes(range(256)),
        ]
        for data in test_cases:
            encoded = base32.base32_encode(data)
            decoded = base32.base32_decode(encoded)
            assert decoded == data, f"Failed for binary data: {data!r}"

    def test_base32_padding(self):
        """Test various padding scenarios."""
        # Different lengths produce different padding
        for length in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
            data = b"A" * length
            encoded = base32.base32_encode(data)
            decoded = base32.base32_decode(encoded)
            assert decoded == data, f"Padding failed for length {length}"
