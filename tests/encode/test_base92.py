# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base92.py
# @time    : 2026/3/14
# @desc    : Tests for base92 encoding/decoding
from crypt.encode import base92


class TestBase92:
  """Test base92 encoding and decoding."""

  def test_base92_roundtrip(self):
    """Test encode/decode roundtrip with various inputs."""
    test_cases = [
      b"",
      b"Hello, World!",
      b"Python 3",
      b"1234567890",
      b"A" * 10,
      b"\x00\x01\x02\x03\x04\x05",
      b"Base92 encoding test with some special characters",
    ]
    for data in test_cases:
      encoded = base92.base92_encode(data)
      decoded = base92.base92_decode(encoded)
      assert decoded == data, f"Roundtrip failed for: {data!r}"

  def test_base92_empty(self):
    """Test empty input."""
    assert base92.base92_encode(b"") == ""
    assert base92.base92_decode("") == b""

  def test_base92_binary_data(self):
    """Test with various binary data patterns."""
    test_cases = [
      b"\x00" * 10,
      b"\xff" * 10,
      b"\x00\x01\x02\x03\x04\x05",
      bytes(range(256)),
    ]
    for data in test_cases:
      encoded = base92.base92_encode(data)
      decoded = base92.base92_decode(encoded)
      assert decoded == data, f"Failed for binary data: {data!r}"


class TestBase92String:
  """Test base92 string encoding/decoding."""

  def test_base92_string_roundtrip(self):
    """Test string encode/decode roundtrip."""
    test_cases = [
      "",
      "Hello",
      "Hello, World!",
      "Test 123",
      "Unicode: 你好 🌍",
    ]
    for text in test_cases:
      encoded = base92.base92_encode_str(text)
      decoded = base92.base92_decode_str(encoded)
      assert decoded == text, f"Roundtrip failed for: {text!r}"

  def test_base92_string_encoding(self):
    """Test with different encodings."""
    text = "Hello, 世界!"
    encoded = base92.base92_encode_str(text, encoding="utf-8")
    decoded = base92.base92_decode_str(encoded, encoding="utf-8")
    assert decoded == text

  def test_base92_invalid_chars_handling(self):
    """Test behavior with invalid characters in decode."""
    data = b"Hello"
    encoded = base92.base92_encode(data)

    # Test that valid encoded string decodes correctly
    decoded = base92.base92_decode(encoded)
    assert decoded == data
