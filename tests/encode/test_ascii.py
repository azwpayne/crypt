# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_ascii.py
# @time    : 2026/3/13
# @desc    : Tests for ASCII encoding/decoding
from crypt.encode import ascii

import pytest


class TestAsciiEncodeDecode:
  """Test ASCII encode/decode functions."""

  def test_ascii_encode_roundtrip(self):
    """Test encode/decode roundtrip."""
    test_cases = [
      "",
      "Hello",
      "World",
      "Python",
      "ASCII",
      "A",
      "The quick brown fox jumps over the lazy dog",
      "!@#$%^&*()",
      "1234567890",
      "\n\t\r",
    ]
    for text in test_cases:
      encoded = ascii.ascii_encode(text)
      decoded = ascii.ascii_decode(encoded)
      assert decoded == text, f"Roundtrip failed for: {text!r}"

  def test_ascii_encode_values(self):
    """Test specific ASCII encoding values."""
    assert ascii.ascii_encode("A") == [65]
    assert ascii.ascii_encode("Hi") == [72, 105]
    assert ascii.ascii_encode("") == []

  def test_ascii_encode_empty(self):
    """Test encoding empty string."""
    assert ascii.ascii_encode("") == []
    assert ascii.ascii_decode([]) == ""

  def test_ascii_encode_non_ascii_error(self):
    """Test that non-ASCII characters raise ValueError."""
    with pytest.raises(ValueError, match="包含非 ASCII 字符"):
      ascii.ascii_encode("你好")

    with pytest.raises(ValueError, match="包含非 ASCII 字符"):
      ascii.ascii_encode("Hello 🌍")

  def test_ascii_decode_invalid_code(self):
    """Test that invalid ASCII codes raise ValueError."""
    with pytest.raises(ValueError, match="无效的 ASCII 码"):
      ascii.ascii_decode([200])

    with pytest.raises(ValueError, match="无效的 ASCII 码"):
      ascii.ascii_decode([-1])

  def test_ascii_type_errors(self):
    """Test type validation."""
    with pytest.raises(TypeError, match="输入必须是字符串"):
      ascii.ascii_encode(123)

    with pytest.raises(TypeError, match="输入必须是列表"):
      ascii.ascii_decode(123)

    with pytest.raises(TypeError, match="ASCII 码必须是整数"):
      ascii.ascii_decode([65, "not an int"])


class TestAsciiHex:
  """Test ASCII hex encoding/decoding."""

  def test_ascii_encode_hex(self):
    """Test hex encoding of ASCII strings."""
    assert ascii.ascii_encode_hex("Hello") == "48656C6C6F"
    assert ascii.ascii_encode_hex("") == ""
    assert ascii.ascii_encode_hex("A") == "41"

  def test_ascii_decode_hex(self):
    """Test hex decoding to ASCII strings."""
    assert ascii.ascii_decode_hex("48656C6C6F") == "Hello"
    assert ascii.ascii_decode_hex("") == ""

  def test_ascii_decode_hex_with_prefix(self):
    """Test hex decoding with 0x prefix."""
    assert ascii.ascii_decode_hex("0x48 0x65 0x6C 0x6C 0x6F") == "Hello"

  def test_ascii_hex_roundtrip(self):
    """Test hex encode/decode roundtrip."""
    test_cases = ["Hello", "World", "Test123", ""]
    for text in test_cases:
      encoded = ascii.ascii_encode_hex(text)
      decoded = ascii.ascii_decode_hex(encoded)
      assert decoded == text, f"Roundtrip failed for: {text!r}"


class TestAsciiBinary:
  """Test ASCII binary encoding/decoding."""

  def test_ascii_encode_binary(self):
    """Test binary encoding of ASCII strings."""
    assert ascii.ascii_encode_binary("Hi") == "01001000 01101001"
    assert ascii.ascii_encode_binary("") == ""
    assert ascii.ascii_encode_binary("A") == "01000001"

  def test_ascii_decode_binary(self):
    """Test binary decoding to ASCII strings."""
    assert ascii.ascii_decode_binary("01001000 01101001") == "Hi"
    assert ascii.ascii_decode_binary("") == ""

  def test_ascii_decode_binary_no_spaces(self):
    """Test binary decoding without spaces."""
    assert ascii.ascii_decode_binary("0100100001101001") == "Hi"

  def test_ascii_binary_roundtrip(self):
    """Test binary encode/decode roundtrip."""
    test_cases = ["Hello", "World", "Test123", ""]
    for text in test_cases:
      encoded = ascii.ascii_encode_binary(text)
      decoded = ascii.ascii_decode_binary(encoded)
      assert decoded == text, f"Roundtrip failed for: {text!r}"

  def test_ascii_decode_binary_invalid(self):
    """Test that invalid binary strings raise ValueError."""
    with pytest.raises(ValueError, match="无效的二进制字符串"):
      ascii.ascii_decode_binary("0102")


class TestAsciiValidation:
  """Test ASCII validation functions."""

  def test_is_ascii_char(self):
    """Test is_ascii_char function."""
    assert ascii.is_ascii_char("A") is True
    assert ascii.is_ascii_char("z") is True
    assert ascii.is_ascii_char("你") is False

    with pytest.raises(TypeError, match="输入必须是单个字符"):
      ascii.is_ascii_char("AB")

    with pytest.raises(TypeError, match="输入必须是单个字符"):
      ascii.is_ascii_char(123)

  def test_is_ascii_string(self):
    """Test is_ascii_string function."""
    assert ascii.is_ascii_string("Hello") is True
    assert ascii.is_ascii_string("Hello123") is True
    assert ascii.is_ascii_string("你好") is False
    assert ascii.is_ascii_string("Hello 世界") is False

    with pytest.raises(TypeError, match="输入必须是字符串"):
      ascii.is_ascii_string(123)

  def test_is_ascii_printable(self):
    """Test is_ascii_printable function."""
    assert ascii.is_ascii_printable("A") is True
    assert ascii.is_ascii_printable(" ") is True
    assert ascii.is_ascii_printable("~") is True
    assert ascii.is_ascii_printable("\n") is False
    assert ascii.is_ascii_printable("\x01") is False

    with pytest.raises(TypeError, match="输入必须是单个字符"):
      ascii.is_ascii_printable("AB")

  def test_ascii_printable_range(self):
    """Test ascii_printable_range function."""
    start, end = ascii.ascii_printable_range()
    assert start == 32
    assert end == 126
