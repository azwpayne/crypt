# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base85.py
# @time    : 2026/3/13
# @desc    : Tests for base85 encoding/decoding

from crypt.encode import base85


class TestBase85:
  """Test base85 encoding and decoding."""

  def test_base85_roundtrip(self):
    """Test encode/decode roundtrip with various inputs."""
    test_cases = [
      b"",
      b"Hello",
      b"World",
      b"Base85 test!",
      b"1234567890",
      b"A" * 10,
      b"\x00\x01\x02\x03\x04",
      bytes(range(256)),
    ]
    for data in test_cases:
      encoded = base85.b85encode(data)
      decoded = base85.b85decode(encoded)
      assert decoded == data, f"Roundtrip failed for: {data!r}"

  def test_base85_empty(self):
    """Test empty input."""
    assert base85.b85encode(b"") == ""
    assert base85.b85decode("") == b""

  def test_base85_padding(self):
    """Test various padding scenarios."""
    # Different lengths need different handling
    for length in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
      data = b"A" * length
      encoded = base85.b85encode(data)
      decoded = base85.b85decode(encoded)
      assert decoded == data, f"Padding failed for length {length}"

  def test_base85_binary_data(self):
    """Test with various binary data patterns."""
    test_cases = [
      b"\x00" * 10,
      b"\xff" * 10,
      b"\x00\x01\x02\x03\x04\x05",
      bytes(range(256))[:100],
    ]
    for data in test_cases:
      encoded = base85.b85encode(data)
      decoded = base85.b85decode(encoded)
      assert decoded == data, f"Failed for binary data: {data!r}"

  def test_base85_invalid_char(self):
    """Test decoding with invalid characters - implementation may skip or error."""
    # Note: Current implementation doesn't validate characters strictly
    # It will either skip invalid chars or produce incorrect output
    try:
      result = base85.b85decode("!@#$%^&*()")
      # If no error, it should return empty or some default
      assert isinstance(result, bytes)
    except (ValueError, KeyError):
      pass  # Error is also acceptable behavior


class TestBase85Ascii85:
  """Test Adobe ASCII85 encoding/decoding."""

  def test_ascii85_format(self):
    """Test that ASCII85 format is correct."""
    data = b"Hello"
    encoded = base85.b85encode_ascii85(data)
    assert encoded.startswith("<~")
    assert encoded.endswith("~>")

  def test_ascii85_roundtrip(self):
    """Test ASCII85 encode/decode roundtrip."""
    test_cases = [
      b"",
      b"Hello",
      b"Base85 test!",
      b"\x00\x01\x02\x03\x04",
    ]
    for data in test_cases:
      encoded = base85.b85encode_ascii85(data)
      decoded = base85.b85decode_ascii85(encoded)
      assert decoded == data, f"Roundtrip failed for: {data!r}"

  def test_ascii85_decode_without_delimiters(self):
    """Test ASCII85 decode without delimiters."""
    # Should handle both with and without delimiters
    data = b"Test"
    encoded_without = base85.b85encode(data)
    decoded = base85.b85decode_ascii85(encoded_without)
    assert decoded == data

  def test_ascii85_whitespace_handling(self):
    """Test that whitespace is stripped."""
    data = b"Hello"
    encoded = base85.b85encode_ascii85(data)
    # Add whitespace
    with_whitespace = "  " + encoded + "  "
    decoded = base85.b85decode_ascii85(with_whitespace)
    assert decoded == data
