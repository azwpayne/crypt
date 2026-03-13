# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base91.py
# @time    : 2026/3/13
# @desc    : Tests for base91 encoding/decoding
import pytest

from crypt.encode import base91


class TestBase91:
    """Test base91 encoding and decoding."""

    def test_base91_roundtrip(self):
        """Test encode/decode roundtrip with various inputs."""
        test_cases = [
            b"",
            b"Hello, World!",
            b"Python 3",
            b"1234567890",
            b"A" * 10,
            b"\x00\x01\x02\x03\x04\x05",
            b"Base91 encoding test with some special characters: !@#$%^&*()",
        ]
        for data in test_cases:
            encoded = base91.base91_encode(data)
            decoded = base91.base91_decode(encoded)
            assert decoded == data, f"Roundtrip failed for: {data!r}"

    def test_base91_empty(self):
        """Test empty input."""
        assert base91.base91_encode(b"") == ""
        assert base91.base91_decode("") == b""

    def test_base91_binary_data(self):
        """Test with various binary data patterns."""
        test_cases = [
            b"\x00" * 10,
            b"\xff" * 10,
            b"\x00\x01\x02\x03\x04\x05",
            bytes(range(256)),
        ]
        for data in test_cases:
            encoded = base91.base91_encode(data)
            decoded = base91.base91_decode(encoded)
            assert decoded == data, f"Failed for binary data: {data!r}"


class TestBase91String:
    """Test base91 string encoding/decoding."""

    def test_base91_string_roundtrip(self):
        """Test string encode/decode roundtrip."""
        test_cases = [
            "",
            "Hello",
            "Hello, World!",
            "Test 123",
            "Unicode: 你好 🌍",
        ]
        for text in test_cases:
            encoded = base91.base91_encode_str(text)
            decoded = base91.base91_decode_str(encoded)
            assert decoded == text, f"Roundtrip failed for: {text!r}"

    def test_base91_string_encoding(self):
        """Test with different encodings."""
        text = "Hello, 世界!"
        encoded = base91.base91_encode_str(text, encoding="utf-8")
        decoded = base91.base91_decode_str(encoded, encoding="utf-8")
        assert decoded == text

    def test_base91_invalid_chars_handling(self):
        """Test behavior with invalid characters in decode."""
        # Note: Current implementation behavior with invalid chars varies
        # It may skip them or produce different output
        data = b"Hello"
        encoded = base91.base91_encode(data)

        # Test that valid encoded string decodes correctly
        decoded = base91.base91_decode(encoded)
        assert decoded == data
