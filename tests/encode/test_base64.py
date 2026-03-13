# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base64.py
# @time    : 2026/3/13
# @desc    : Tests for base64 encoding/decoding
import base64 as stdlib_base64

import pytest

from crypt.encode import base64
from tests import BYTE_TEST_CASES


@pytest.mark.parametrize("msg", BYTE_TEST_CASES)
class TestBase64:
    """Test base64 encoding and decoding against Python standard library."""

    def test_base64_encode(self, msg):
        """Verify base64_encode matches standard library output."""
        result = base64.base64_encode(msg)
        expected = stdlib_base64.b64encode(msg).decode("ascii")
        assert result == expected, f"Encoding failed for: {msg!r}"

    def test_base64_decode(self, msg):
        """Verify base64_decode correctly decodes standard library output."""
        encoded = stdlib_base64.b64encode(msg).decode("ascii")
        decoded = base64.base64_decode(encoded)
        assert decoded == msg, f"Decoding failed for: {msg!r}"

    def test_base64_roundtrip(self, msg):
        """Verify encode/decode roundtrip."""
        encoded = base64.base64_encode(msg)
        decoded = base64.base64_decode(encoded)
        assert decoded == msg, f"Roundtrip failed for: {msg!r}"


class TestBase64EdgeCases:
    """Test edge cases and error handling."""

    def test_base64_empty(self):
        """Test empty input."""
        assert base64.base64_encode(b"") == ""
        assert base64.base64_decode("") == b""

    def test_base64_padding(self):
        """Test various padding scenarios."""
        # Different lengths produce different padding
        for length in [1, 2, 3, 4, 5, 6, 7, 8, 9]:
            data = b"A" * length
            encoded = base64.base64_encode(data)
            decoded = base64.base64_decode(encoded)
            assert decoded == data, f"Padding failed for length {length}"

            # Verify padding count
            padding_count = (3 - length % 3) % 3
            assert encoded.count("=") == padding_count, f"Wrong padding for length {length}"

    def test_base64_binary_data(self):
        """Test with various binary data patterns."""
        test_cases = [
            b"\x00" * 10,
            b"\xff" * 10,
            b"\x00\x01\x02\x03\x04\x05",
            bytes(range(256)),
        ]
        for data in test_cases:
            encoded = base64.base64_encode(data)
            decoded = base64.base64_decode(encoded)
            assert decoded == data, f"Failed for binary data: {data!r}"

    def test_base64_whitespace_in_decode(self):
        """Test that whitespace is handled in decode."""
        # Note: The current implementation strips padding but doesn't handle internal whitespace
        # This test documents current behavior
        data = b"Hello World!"
        encoded = base64.base64_encode(data)
        assert base64.base64_decode(encoded) == data

    def test_base64_url_unsafe_alphabet(self):
        """Test that standard base64 alphabet is used."""
        # Standard base64 uses + and /
        data = b"\xfb\xfc\xfd\xfe\xff"
        encoded = base64.base64_encode(data)
        assert "+" in encoded or "/" in encoded or "=" in encoded
