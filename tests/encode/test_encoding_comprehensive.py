"""Comprehensive tests for all encoding algorithms.

Tests for Base encoding (16, 32, 36, 58, 62, 64, 85, 91, 92),
hex/bin conversion, and other encoding utilities.
"""

from __future__ import annotations

import base64 as stdlib_base64
from crypt.encode.base16 import base16_decode, base16_encode
from crypt.encode.base32 import base32_decode, base32_encode
from crypt.encode.base36 import base36_decode, base36_encode
from crypt.encode.base58 import (
  decode_base58,
  decode_base58_check,
  encode_base58,
  encode_base58_check,
)
from crypt.encode.base62 import base62_decode, base62_encode
from crypt.encode.base64 import base64_decode, base64_encode
from crypt.encode.base85 import base85_decode, base85_encode
from crypt.encode.base91 import base91_decode, base91_encode
from crypt.encode.base92 import base92_decode, base92_encode
from crypt.encode.hex2bin import (
  batch_bin_to_hex,
  batch_hex_to_bin,
  bin_bits_to_hex,
  bin_byte_to_hex,
  bin_to_hex,
  bin_to_hex_grouped,
  bin_to_hex_with_prefix,
  byte_array_to_hex,
  hex_byte_to_bin,
  hex_to_bin,
  hex_to_bin_array,
  hex_to_bin_grouped,
  is_valid_bin,
  is_valid_hex,
)

import pytest

from tests import BYTE_TEST_CASES


class TestBase16:
  """Comprehensive tests for Base16 (hex) encoding."""

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_roundtrip(self, msg):
    """Test Base16 encode/decode roundtrip."""
    encoded = base16_encode(msg)
    decoded = base16_decode(encoded)
    assert decoded == msg

  def test_empty(self):
    """Test empty input."""
    assert base16_encode(b"") == ""
    assert base16_decode("") == b""

  def test_known_values(self):
    """Test known hex values."""
    assert base16_encode(b"\x00") == "00"
    assert base16_encode(b"\xff") == "FF"
    assert base16_encode(b"\xde\xad\xbe\xef") == "DEADBEEF"

  def test_decode_lowercase(self):
    """Test decoding lowercase hex."""
    assert base16_decode("deadbeef") == b"\xde\xad\xbe\xef"
    assert base16_decode("DeAdBeEf") == b"\xde\xad\xbe\xef"


class TestBase32:
  """Comprehensive tests for Base32 encoding."""

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_roundtrip(self, msg):
    """Test Base32 encode/decode roundtrip."""
    encoded = base32_encode(msg)
    decoded = base32_decode(encoded)
    assert decoded == msg

  def test_empty(self):
    """Test empty input."""
    assert base32_encode(b"") == ""
    assert base32_decode("") == b""

  @pytest.mark.parametrize(
    ("data", "expected_prefix"),
    [
      (b"f", "MY"),
      (b"fo", "MZXQ"),
      (b"foo", "MZXW6"),
      (b"foob", "MZXW6YQ"),
      (b"fooba", "MZXW6YTB"),
      (b"foobar", "MZXW6YTBOI"),
    ],
  )
  def test_rfc4648_vectors(self, data, expected_prefix):
    """Test RFC 4648 test vectors."""
    encoded = base32_encode(data)
    assert encoded.rstrip("=").startswith(expected_prefix)

  def test_invalid_character(self):
    """Test invalid character handling."""
    with pytest.raises(ValueError, match="Invalid Base32 character"):
      base32_decode("INVALID!")


class TestBase36:
  """Comprehensive tests for Base36 encoding."""

  def test_roundtrip_integers(self):
    """Test Base36 encode/decode with integers."""
    for num in [0, 1, 10, 35, 36, 100, 1000, 12345678]:
      encoded = base36_encode(num)
      decoded = base36_decode(encoded)
      assert decoded == num

  def test_known_values(self):
    """Test known Base36 values."""
    assert base36_encode(0) == "0"
    assert base36_encode(10) == "a"
    assert base36_encode(35) == "z"
    assert base36_encode(36) == "10"

  def test_case_insensitivity(self):
    """Test case insensitive decoding."""
    assert base36_decode("abc") == base36_decode("ABC")


class TestBase58:
  """Comprehensive tests for Base58 encoding."""

  @pytest.mark.parametrize(
    "data",
    [
      b"",
      b"\x00",
      b"\x00\x00",
      b"Hello World!",
      b"\xff\xff\xff\xff",
      b"\x00\x01\x02\x03\x04\x05",
      bytes(range(256)),
    ],
  )
  def test_roundtrip(self, data):
    """Test Base58 encode/decode roundtrip."""
    encoded = encode_base58(data)
    decoded = decode_base58(encoded)
    assert decoded == data

  def test_leading_zeros(self):
    """Test leading zeros handling."""
    # Each leading zero byte becomes '1' in Base58
    assert encode_base58(b"\x00").startswith("1")
    assert encode_base58(b"\x00\x00").startswith("11")
    assert encode_base58(b"\x00\x00\x00").startswith("111")

  def test_no_confusing_characters(self):
    """Test that confusing characters are not in output."""
    data = bytes(range(256))
    encoded = encode_base58(data)
    # Base58 excludes 0, O, I, l
    assert "0" not in encoded
    assert "O" not in encoded
    assert "I" not in encoded
    assert "l" not in encoded

  def test_invalid_character(self):
    """Test invalid character handling."""
    with pytest.raises(ValueError, match="无效的Base58字符"):
      decode_base58("Invalid0")  # '0' is not in Base58

  @pytest.mark.parametrize(
    "data",
    [
      b"Test",
      b"Hello Bitcoin!",
      b"\x00\x01\x02\x03",
    ],
  )
  def test_base58check_roundtrip(self, data):
    """Test Base58Check encode/decode roundtrip."""
    encoded = encode_base58_check(data)
    decoded = decode_base58_check(encoded)
    assert decoded == data

  def test_base58check_corruption_detection(self):
    """Test Base58Check detects corruption."""
    data = b"Test data"
    encoded = encode_base58_check(data)
    # Corrupt the last character
    corrupted = encoded[:-1] + ("2" if encoded[-1] == "1" else "1")
    with pytest.raises(ValueError, match="校验和"):
      decode_base58_check(corrupted)


class TestBase62:
  """Comprehensive tests for Base62 encoding."""

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_roundtrip(self, msg):
    """Test Base62 encode/decode roundtrip."""
    encoded = base62_encode(msg)
    decoded = base62_decode(encoded)
    assert decoded == msg

  def test_empty(self):
    """Test empty input."""
    result = base62_encode(b"")
    assert base62_decode(result) == b""

  def test_alphanumeric_only(self):
    """Test that output contains only alphanumeric characters."""
    data = bytes(range(256))
    encoded = base62_encode(data)
    assert all(c.isalnum() for c in encoded)


class TestBase64:
  """Comprehensive tests for Base64 encoding."""

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_vs_stdlib(self, msg):
    """Test against Python standard library."""
    result = base64_encode(msg)
    expected = stdlib_base64.b64encode(msg).decode("ascii")
    assert result == expected

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_roundtrip(self, msg):
    """Test Base64 encode/decode roundtrip."""
    encoded = base64_encode(msg)
    decoded = base64_decode(encoded)
    assert decoded == msg

  def test_empty(self):
    """Test empty input."""
    assert base64_encode(b"") == ""
    assert base64_decode("") == b""

  def test_padding(self):
    """Test various padding scenarios."""
    for length in range(1, 10):
      data = b"A" * length
      encoded = base64_encode(data)
      # Padding count should be (3 - length % 3) % 3
      expected_padding = (3 - length % 3) % 3
      assert encoded.count("=") == expected_padding


class TestBase85:
  """Comprehensive tests for Base85 encoding."""

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_roundtrip(self, msg):
    """Test Base85 encode/decode roundtrip."""
    encoded = base85_encode(msg)
    decoded = base85_decode(encoded)
    assert decoded == msg

  def test_empty(self):
    """Test empty input."""
    assert base85_encode(b"") == ""
    assert base85_decode("") == b""


class TestBase91:
  """Comprehensive tests for Base91 encoding."""

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_roundtrip(self, msg):
    """Test Base91 encode/decode roundtrip."""
    encoded = base91_encode(msg)
    decoded = base91_decode(encoded)
    assert decoded == msg

  def test_empty(self):
    """Test empty input."""
    assert base91_encode(b"") == ""
    assert base91_decode("") == b""


class TestBase92:
  """Comprehensive tests for Base92 encoding."""

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_roundtrip(self, msg):
    """Test Base92 encode/decode roundtrip."""
    encoded = base92_encode(msg)
    decoded = base92_decode(encoded)
    assert decoded == msg

  def test_empty(self):
    """Test empty input."""
    assert base92_encode(b"") == ""
    assert base92_decode("") == b""


class TestHex2Bin:
  """Comprehensive tests for hex/binary conversion utilities."""

  @pytest.mark.parametrize(
    ("hex_str", "expected"),
    [
      ("1", "1"),
      ("F", "1111"),
      ("FF", "11111111"),
      ("0xFF", "11111111"),
      ("1A3F", "1101000111111"),
    ],
  )
  def test_hex_to_bin(self, hex_str, expected):
    """Test hex to binary conversion."""
    result = hex_to_bin(hex_str)
    assert result == expected

  def test_hex_to_bin_min_bits(self):
    """Test hex to binary with minimum bits."""
    assert hex_to_bin("F", 8) == "00001111"
    assert hex_to_bin("FF", 8) == "11111111"
    assert hex_to_bin("1", 4) == "0001"

  def test_hex_to_bin_grouped(self):
    """Test grouped hex to binary conversion."""
    result = hex_to_bin_grouped("4D61726B", 8)
    assert result == "01001101 01100001 01110010 01101011"

  def test_hex_to_bin_array(self):
    """Test hex to binary array conversion."""
    result = hex_to_bin_array("F")
    assert result == [1, 1, 1, 1]

  def test_hex_byte_to_bin(self):
    """Test single byte hex to binary."""
    assert hex_byte_to_bin("F") == "00001111"
    assert hex_byte_to_bin("FF") == "11111111"
    assert hex_byte_to_bin("A", with_prefix=True) == "0b00001010"

  @pytest.mark.parametrize(
    ("bin_str", "expected"),
    [
      ("1", "1"),
      ("1111", "F"),
      ("11111111", "FF"),
      ("0b1111", "F"),
      ("1101 0010", "D2"),
    ],
  )
  def test_bin_to_hex(self, bin_str, expected):
    """Test binary to hex conversion."""
    result = bin_to_hex(bin_str)
    assert result == expected

  def test_bin_to_hex_grouped(self):
    """Test grouped binary to hex conversion."""
    result = bin_to_hex_grouped("01001101011000010111001001101011", 1)
    assert result == "4D 61 72 6B"

  def test_bin_byte_to_hex(self):
    """Test single byte binary to hex."""
    assert bin_byte_to_hex("1111") == "0F"
    assert bin_byte_to_hex("11010010") == "D2"

  def test_bin_to_hex_with_prefix(self):
    """Test binary to hex with prefix."""
    assert bin_to_hex_with_prefix("11111111") == "0xFF"

  def test_is_valid_hex(self):
    """Test hex validation."""
    assert is_valid_hex("1a2B3c") is True
    assert is_valid_hex("0xAB12") is True
    assert is_valid_hex("GHIJ") is False

  def test_is_valid_bin(self):
    """Test binary validation."""
    assert is_valid_bin("101010") is True
    assert is_valid_bin("0b101010") is True
    assert is_valid_bin("10201") is False

  def test_bin_bits_to_hex(self):
    """Test bit list to hex conversion."""
    assert bin_bits_to_hex([0, 0, 1, 1, 1, 1]) == "F"
    assert bin_bits_to_hex([1, 1, 1, 1, 1, 1, 1, 1]) == "FF"

  def test_byte_array_to_hex(self):
    """Test byte array to hex conversion."""
    assert byte_array_to_hex([77, 97, 114, 107]) == "4D61726B"
    assert byte_array_to_hex([255, 0, 255]) == "FF00FF"

  def test_batch_hex_to_bin(self):
    """Test batch hex to binary conversion."""
    result = batch_hex_to_bin(["1", "A", "FF"])
    assert result == ["1", "1010", "11111111"]

  def test_batch_bin_to_hex(self):
    """Test batch binary to hex conversion."""
    result = batch_bin_to_hex(["1", "1010", "11111111"])
    assert result == ["1", "A", "FF"]

  def test_invalid_hex_raises(self):
    """Test invalid hex raises ValueError."""
    with pytest.raises(ValueError, match="输入不能为空"):
      hex_to_bin("")
    with pytest.raises(ValueError, match="无效的十六进制字符串"):
      hex_to_bin("GHI")

  def test_invalid_bin_raises(self):
    """Test invalid binary raises ValueError."""
    with pytest.raises(ValueError, match="输入不能为空"):
      bin_to_hex("")
    with pytest.raises(ValueError, match="无效的二进制字符串"):
      bin_to_hex("102")


class TestEncodingEdgeCases:
  """Edge case tests for all encoding algorithms."""

  def test_binary_data_all_bytes(self):
    """Test with binary data containing all byte values."""
    data = bytes(range(256))

    # Test all Base encodings
    assert base16_decode(base16_encode(data)) == data
    assert base32_decode(base32_encode(data)) == data
    assert decode_base58(encode_base58(data)) == data
    assert base62_decode(base62_encode(data)) == data
    assert base64_decode(base64_encode(data)) == data
    assert base85_decode(base85_encode(data)) == data
    assert base91_decode(base91_encode(data)) == data
    assert base92_decode(base92_encode(data)) == data

  def test_large_data(self):
    """Test with large data."""
    data = b"x" * 10000

    assert base64_decode(base64_encode(data)) == data
    assert base32_decode(base32_encode(data)) == data
    assert decode_base58(encode_base58(data)) == data

  def test_unicode_bytes(self):
    """Test with UTF-8 encoded Unicode data."""
    data = "Hello, 世界! 🌍".encode()

    assert base64_decode(base64_encode(data)) == data
    assert base32_decode(base32_encode(data)) == data
    assert decode_base58(encode_base58(data)) == data

  def test_determinism(self):
    """Test encoding is deterministic."""
    data = b"test data"

    results64 = [base64_encode(data) for _ in range(10)]
    assert all(r == results64[0] for r in results64)

    results58 = [encode_base58(data) for _ in range(10)]
    assert all(r == results58[0] for r in results58)
