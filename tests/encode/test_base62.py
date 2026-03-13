# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base62.py
# @time    : 2026/3/13
# @desc    : Tests for base62 encoding/decoding
import pytest

from crypt.encode import base62


class TestBase62:
    """Test base62 integer encoding and decoding."""

    # Known test vectors for 0-9A-Za-z alphabet
    TEST_VECTORS = [
        (0, "0"),
        (1, "1"),
        (10, "A"),
        (35, "Z"),  # Uppercase Z is at index 35
        (61, "z"),  # Lowercase z is at index 61
        (62, "10"),
        (100, "1c"),  # 100 = 1*62 + 38, index 38 is 'c'
        (1000, "G8"),
        (123456789, "8M0kX"),
        (9876543210, "AmOy42"),
    ]

    @pytest.mark.parametrize(("num", "expected"), TEST_VECTORS)
    def test_base62_encode(self, num, expected):
        """Verify base62_encode produces expected output."""
        result = base62.encode(num)
        assert result == expected, f"Expected {expected!r}, got {result!r}"

    @pytest.mark.parametrize(("num", "expected"), TEST_VECTORS)
    def test_base62_decode(self, num, expected):
        """Verify base62_decode correctly decodes known values."""
        result = base62.decode(expected)
        assert result == num, f"Expected {num}, got {result}"

    def test_base62_roundtrip(self):
        """Test encode/decode roundtrip with various numbers."""
        test_numbers = [
            0,
            1,
            10,
            100,
            1000,
            123456789,
            9876543210,
            10**18,
            2**63 - 1,  # Max int64
        ]
        for num in test_numbers:
            encoded = base62.encode(num)
            decoded = base62.decode(encoded)
            assert decoded == num, f"Roundtrip failed for: {num}"

    def test_base62_large_numbers(self):
        """Test with very large numbers."""
        large_numbers = [
            10**50,
            2**256,  # Large number (like a private key)
        ]
        for num in large_numbers:
            encoded = base62.encode(num)
            decoded = base62.decode(encoded)
            assert decoded == num, f"Roundtrip failed for large number: {num}"

    def test_base62_invalid_char(self):
        """Test decoding with invalid characters."""
        with pytest.raises(ValueError, match="无效的 base62 字符"):
            base62.decode("abc@123")

        with pytest.raises(ValueError, match="无效的 base62 字符"):
            base62.decode("ABC-123")

    def test_base62_empty_decode(self):
        """Test decoding empty string."""
        with pytest.raises(ValueError, match="空字符串无法解码"):
            base62.decode("")

    def test_base62_whitespace_stripping(self):
        """Test that whitespace is stripped during decode."""
        assert base62.decode("  1c  ") == 100
        assert base62.decode("\t10\n") == 62


class TestBase62Validation:
    """Test base62 validation function."""

    def test_is_valid_base62_valid(self):
        """Test valid base62 strings."""
        valid_strings = ["abc123", "ABC123", "123456", "aZ09", "0"]
        for s in valid_strings:
            assert base62.is_valid_base62(s), f"Should be valid: {s!r}"

    def test_is_valid_base62_invalid(self):
        """Test invalid base62 strings."""
        invalid_strings = ["abc@123", "ABC-123", "hello world", "", "你好"]
        for s in invalid_strings:
            assert not base62.is_valid_base62(s), f"Should be invalid: {s!r}"

    def test_is_valid_base62_edge_cases(self):
        """Test edge cases for validation."""
        assert not base62.is_valid_base62("")  # Empty string
        assert base62.is_valid_base62("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
