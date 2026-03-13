# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base58.py
# @time    : 2026/3/13
# @desc    : Tests for base58 encoding/decoding
import pytest

from crypt.encode import base58


class TestBase58:
    """Test base58 encoding and decoding."""
    # Known test vectors for base58 (standard base58 encoding)
    # Empty input produces empty output
    TEST_VECTORS = [
        (b"", ""),
        (b"\x00", "1"),
        (b"\x00\x00", "11"),
        (b"Hello World!", "2NEpo7TZRRrLZSi2U"),
        (b"\x00\x01\x02\x03", "1Ldp"),
        (b"The quick brown fox jumps over the lazy dog.",
         "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"),
    ]

    @pytest.mark.parametrize(("data", "expected"), TEST_VECTORS)
    def test_base58_encode(self, data, expected):
        """Verify base58_encode produces expected output."""
        result = base58.encode_base58(data)
        assert result == expected, f"Expected {expected!r}, got {result!r}"

    @pytest.mark.parametrize(("data", "expected"), TEST_VECTORS)
    def test_base58_decode(self, data, expected):
        """Verify base58_decode correctly decodes known values."""
        result = base58.decode_base58(expected)
        assert result == data, f"Expected {data!r}, got {result!r}"

    def test_base58_roundtrip(self):
        """Test encode/decode roundtrip with various inputs."""
        test_cases = [
            b"",
            b"\x00",
            b"\x00\x00",
            b"Hello World!",
            b"\x00\x01\x02\x03\x04\x05",
            b"Binary\xff\xfe\xfd",
            b"A" * 100,
        ]
        for data in test_cases:
            encoded = base58.encode_base58(data)
            decoded = base58.decode_base58(encoded)
            assert decoded == data, f"Roundtrip failed for: {data!r}"

    def test_base58_invalid_char(self):
        """Test decoding with invalid characters."""
        with pytest.raises(ValueError, match="无效的Base58字符"):
            base58.decode_base58("A0OIl")  # 0, O, I, l are invalid in base58

    def test_base58_leading_zeros(self):
        """Test handling of leading zeros."""
        # Leading zeros become '1's in base58
        test_cases = [
            (b"\x00", "1"),
            (b"\x00\x00", "11"),
            (b"\x00\x00\x00", "111"),
            (b"\x00Hello", "19Ajdvzr"),
        ]
        for data, expected in test_cases:
            encoded = base58.encode_base58(data)
            assert encoded == expected, f"Failed for {data!r}"
            decoded = base58.decode_base58(encoded)
            assert decoded == data, f"Roundtrip failed for {data!r}"


class TestBase58Check:
    """Test base58check encoding/decoding with checksum."""

    def test_base58check_roundtrip(self):
        """Test encode/decode roundtrip with checksum."""
        test_cases = [
            b"",
            b"Test data",
            b"\x00\x01\x02\x03",
            b"A" * 50,
        ]
        for data in test_cases:
            encoded = base58.encode_base58_check(data)
            decoded = base58.decode_base58_check(encoded)
            assert decoded == data, f"Roundtrip failed for: {data!r}"

    def test_base58check_invalid_checksum(self):
        """Test that corrupted checksum is detected."""
        data = b"Test data for checksum"
        encoded = base58.encode_base58_check(data)

        # Corrupt the last character
        corrupted = encoded[:-1] + ("2" if encoded[-1] == "1" else "1")

        with pytest.raises(ValueError, match="校验和验证失败"):
            base58.decode_base58_check(corrupted)

    def test_base58check_too_short(self):
        """Test that too short input raises error."""
        with pytest.raises(ValueError, match="Base58Check数据太短"):
            base58.decode_base58_check("1")  # Too short to contain checksum
