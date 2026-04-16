# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_hex2bin.py
# @time    : 2026/3/13
# @desc    : Tests for hex2bin conversion functions
from crypt.encode import hex2bin

import pytest


class TestHexToBin:
  """Test hex to binary conversion."""

  def test_hex_to_bin_basic(self):
    """Test basic hex to binary conversion."""
    assert hex2bin.hex_to_bin("FF") == "11111111"
    assert hex2bin.hex_to_bin("00") == "0"
    assert hex2bin.hex_to_bin("1A3F") == "1101000111111"

  def test_hex_to_bin_with_prefix(self):
    """Test hex with 0x prefix."""
    assert hex2bin.hex_to_bin("0xFF") == "11111111"
    assert hex2bin.hex_to_bin("0x0A") == "1010"

  def test_hex_to_bin_with_spaces(self):
    """Test hex with spaces."""
    assert hex2bin.hex_to_bin("12 34") == "1001000110100"
    assert hex2bin.hex_to_bin("FF FF") == "1111111111111111"

  def test_hex_to_bin_min_bits(self):
    """Test hex to binary with minimum bits."""
    assert hex2bin.hex_to_bin("FF", min_bits=16) == "0000000011111111"
    assert hex2bin.hex_to_bin("1", min_bits=8) == "00000001"

  def test_hex_to_bin_empty(self):
    """Test empty input raises ValueError."""
    with pytest.raises(ValueError, match="输入不能为空"):
      hex2bin.hex_to_bin("")

  def test_hex_to_bin_invalid(self):
    """Test invalid hex raises ValueError."""
    with pytest.raises(ValueError, match="无效的十六进制字符串"):
      hex2bin.hex_to_bin("GGGG")

  def test_hex_to_bin_grouped(self):
    """Test grouped hex to binary conversion."""
    result = hex2bin.hex_to_bin_grouped("4D61726B", 8)
    assert result == "01001101 01100001 01110010 01101011"

  def test_hex_to_bin_grouped_padding(self):
    """Test grouped hex to binary with padding."""
    result = hex2bin.hex_to_bin_grouped("1", 8)
    assert result == "00000001"

  def test_hex_to_bin_array(self):
    """Test hex to bit array conversion."""
    result = hex2bin.hex_to_bin_array("3F")
    assert result == [1, 1, 1, 1, 1, 1]

  def test_hex_byte_to_bin(self):
    """Test single byte hex to binary."""
    assert hex2bin.hex_byte_to_bin("F") == "00001111"
    assert hex2bin.hex_byte_to_bin("A") == "00001010"
    assert hex2bin.hex_byte_to_bin("FF") == "11111111"

  def test_hex_byte_to_bin_with_prefix(self):
    """Test single byte with prefix."""
    assert hex2bin.hex_byte_to_bin("F", with_prefix=True) == "0b00001111"

  def test_hex_byte_to_bin_invalid_length(self):
    """Test invalid length raises ValueError."""
    with pytest.raises(ValueError, match="单字节输入长度必须为1或2"):
      hex2bin.hex_byte_to_bin("FFF")


class TestBinToHex:
  """Test binary to hex conversion."""

  def test_bin_to_hex_basic(self):
    """Test basic binary to hex conversion."""
    assert hex2bin.bin_to_hex("11111111") == "FF"
    assert hex2bin.bin_to_hex("0000") == "0"
    assert hex2bin.bin_to_hex("1101000111111") == "1A3F"

  def test_bin_to_hex_with_0b_prefix(self):
    """Test binary with 0b prefix."""
    assert hex2bin.bin_to_hex("0b11111111") == "FF"
    assert hex2bin.bin_to_hex("0b1010") == "A"

  def test_bin_to_hex_with_spaces(self):
    """Test binary with spaces."""
    assert hex2bin.bin_to_hex("1111 1111") == "FF"
    assert hex2bin.bin_to_hex("1101 0010") == "D2"

  def test_bin_to_hex_min_digits(self):
    """Test binary to hex with minimum digits."""
    assert hex2bin.bin_to_hex("1111", min_digits=4) == "000F"
    assert hex2bin.bin_to_hex("1", min_digits=2) == "01"

  def test_bin_to_hex_empty(self):
    """Test empty input raises ValueError."""
    with pytest.raises(ValueError, match="输入不能为空"):
      hex2bin.bin_to_hex("")

  def test_bin_to_hex_invalid(self):
    """Test invalid binary raises ValueError."""
    with pytest.raises(ValueError, match="无效的二进制字符串"):
      hex2bin.bin_to_hex("10201")

  def test_bin_to_hex_grouped(self):
    """Test grouped binary to hex conversion."""
    result = hex2bin.bin_to_hex_grouped("01001101011000010111001001101011", 1)
    assert result == "4D 61 72 6B"

  def test_bin_to_hex_grouped_padding(self):
    """Test grouped binary to hex with padding."""
    result = hex2bin.bin_to_hex_grouped("1", 2)
    assert result == "0001"

  def test_bin_byte_to_hex(self):
    """Test single byte binary to hex."""
    assert hex2bin.bin_byte_to_hex("1111") == "0F"
    assert hex2bin.bin_byte_to_hex("11010010") == "D2"

  def test_bin_byte_to_hex_too_long(self):
    """Test single byte binary too long raises ValueError."""
    with pytest.raises(ValueError, match="单字节输入不能超过8位"):
      hex2bin.bin_byte_to_hex("111111111")

  def test_bin_to_hex_with_prefix(self):
    """Test binary to hex with custom prefix."""
    assert hex2bin.bin_to_hex_with_prefix("11111111") == "0xFF"
    assert hex2bin.bin_to_hex_with_prefix("1111", prefix="$") == "$F"


class TestValidation:
  """Test validation functions."""

  def test_is_valid_hex_valid(self):
    """Test valid hex strings."""
    assert hex2bin.is_valid_hex("1A2B") is True
    assert hex2bin.is_valid_hex("0xAB12") is True
    assert hex2bin.is_valid_hex("1a2b3c") is True

  def test_is_valid_hex_invalid(self):
    """Test invalid hex strings."""
    assert hex2bin.is_valid_hex("0xZZ") is False
    assert hex2bin.is_valid_hex("") is False
    assert hex2bin.is_valid_hex("GGGG") is False

  def test_is_valid_bin_valid(self):
    """Test valid binary strings."""
    assert hex2bin.is_valid_bin("101010") is True
    assert hex2bin.is_valid_bin("0b1010") is True
    assert hex2bin.is_valid_bin("11110000") is True

  def test_is_valid_bin_invalid(self):
    """Test invalid binary strings."""
    assert hex2bin.is_valid_bin("0b10201") is False
    assert hex2bin.is_valid_bin("") is False
    assert hex2bin.is_valid_bin("10201") is False

  def test_is_valid_bin_non_string(self):
    """Test is_valid_bin with non-string input."""
    # Note: is_valid_bin catches TypeError, but None.replace() raises
    # AttributeError. Passing an int triggers TypeError on replace().
    assert hex2bin.is_valid_bin(123) is False  # type: ignore[arg-type]


class TestBitListConversions:
  """Test bit list conversions."""

  def test_bin_bits_to_hex(self):
    """Test bit list to hex."""
    assert hex2bin.bin_bits_to_hex([0, 0, 1, 1, 1, 1]) == "F"
    assert hex2bin.bin_bits_to_hex([1, 1, 1, 1]) == "F"

  def test_bin_bits_to_hex_invalid(self):
    """Test invalid bit list raises ValueError."""
    with pytest.raises(ValueError, match="列表只能包含0或1"):
      hex2bin.bin_bits_to_hex([0, 1, 2])

  def test_byte_array_to_hex(self):
    """Test byte array to hex."""
    assert hex2bin.byte_array_to_hex([77, 97, 114, 107]) == "4D61726B"
    assert hex2bin.byte_array_to_hex([0, 255]) == "00FF"

  def test_byte_array_to_hex_invalid(self):
    """Test invalid byte array raises ValueError."""
    with pytest.raises(ValueError, match="字节值必须在0-255范围内"):
      hex2bin.byte_array_to_hex([256])

    with pytest.raises(ValueError, match="字节值必须在0-255范围内"):
      hex2bin.byte_array_to_hex([-1])


class TestBatchConversions:
  """Test batch conversion functions."""

  def test_batch_hex_to_bin(self):
    """Test batch hex to binary."""
    result = hex2bin.batch_hex_to_bin(["1", "A", "FF"])
    assert result == ["1", "1010", "11111111"]

  def test_batch_bin_to_hex(self):
    """Test batch binary to hex."""
    result = hex2bin.batch_bin_to_hex(["1", "1010", "11111111"])
    assert result == ["1", "A", "FF"]


class TestRoundtrip:
  """Test roundtrip conversions."""

  def test_hex_bin_roundtrip(self):
    """Test hex -> bin -> hex roundtrip."""
    hex_values = ["1A3F", "00", "FF", "DEADBEEF"]
    for hex_val in hex_values:
      bin_val = hex2bin.hex_to_bin(hex_val)
      hex_result = hex2bin.bin_to_hex(bin_val)
      # Normalize: bin_to_hex pads to 4 bits, so we need to compare properly
      expected = hex_val.lstrip("0") or "0"
      result = hex_result.lstrip("0") or "0"
      assert result.upper() == expected.upper()

  def test_bin_hex_roundtrip(self):
    """Test bin -> hex -> bin roundtrip."""
    bin_values = ["11111111", "0000", "10101010", "1101000111111"]
    for bin_val in bin_values:
      hex_val = hex2bin.bin_to_hex(bin_val)
      # Convert back - need to handle padding
      expected_int = int(bin_val, 2)
      result_bin = hex2bin.hex_to_bin(hex_val)
      result_int = int(result_bin, 2)
      assert result_int == expected_int
