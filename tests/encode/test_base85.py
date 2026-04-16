# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base85.py
# @time    : 2026/3/13
# @desc    : Tests for base85 encoding/decoding

from crypt.encode import base85

import pytest


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
    """Test decoding with invalid characters raises ValueError."""
    with pytest.raises(ValueError, match="Invalid Base85 character"):
      base85.b85decode("!@#$%^&*()~")

  def test_base85_struct_error(self):
    """Test decoding with value that causes struct error."""
    # A chunk of 5 'u's decodes to value 0xFFFFFFFF which packs fine,
    # but we need a value that doesn't fit in 4 bytes.
    # The max value from 5 base85 chars is 84*85^4 + 84*85^3 + 84*85^2 + 84*85 + 84
    # = 84 * (85^5 - 1) / 84 = 85^5 - 1 = 4437053125 - 1 = 4437053124
    # which is > 0xFFFFFFFF = 4294967295, so it should cause struct.error.
    # Character '~' is not in the alphabet, so let's use a different approach.
    # Actually, the valid max is 'uuuuu' = 4294967295 = 0xFFFFFFFF.
    # Any character beyond 'u' would be invalid. Let's just trust the code path.
    # The struct.error path is triggered when value > 0xFFFFFFFF.
    # Since each char is validated against the alphabet (0-84), max is 84.
    # Max value = 84*(85^4+85^3+85^2+85+1) = 84*52200625/84 = 52200625... wait.
    # 85^5 = 4437053125. Max 5-digit base85 = 85^5 - 1 = 4437053124 > 2^32-1.
    # So 'uuuuu' = 84*85^4 + 84*85^3 + 84*85^2 + 84*85 + 84
    # = 84*(52200625 + 614125 + 7225 + 85 + 1) = 84*52822061 = 4437053124.
    # But u = 83, not 84! The alphabet has 85 chars, indices 0-84.
    # 'u' is index 83 (let me check alphabet).
    # Alphabet: !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstu
    # 'u' is the last character, index 84. So 'uuuuu' gives max value.
    # 84 * (85^4 + 85^3 + 85^2 + 85 + 1) = 84 * 52200625 / wait, that's geometric series.
    # Sum = (85^5 - 1) / (85 - 1) = 4437053124 / 84 = 52822061. Then * 84 = 4437053124.
    # 4437053124 > 4294967295, so struct.error should be raised.
    with pytest.raises(ValueError, match="Error unpacking"):
      base85.b85decode("uuuuu")


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


class TestBase85EdgeCases:
  def test_base85_encode_decode_roundtrip(self):
    """Test base85 encode/decode roundtrip."""
    data = b"Hello, World!"
    encoded = base85.b85encode(data)
    decoded = base85.b85decode(encoded)
    assert decoded == data

  def test_base85_empty_data(self):
    """Test base85 with empty data."""
    assert base85.b85encode(b"") == ""

  def test_base85_binary_data(self):
    """Test base85 with binary data."""
    data = bytes(range(256))
    encoded = base85.b85encode(data)
    decoded = base85.b85decode(encoded)
    assert decoded == data

  def test_base85_single_byte(self):
    """Test base85 with single byte."""
    encoded = base85.b85encode(b"A")
    decoded = base85.b85decode(encoded)
    assert decoded == b"A"
