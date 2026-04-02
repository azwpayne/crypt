# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base32.py
# @time    : 2026/3/13
# @desc    : Tests for base32 encoding/decoding
import base64
from crypt.encode import base32

import pytest

from tests import BYTE_TEST_CASES


@pytest.mark.parametrize("msg", BYTE_TEST_CASES)
class TestBase32:
  """Test base32 encoding and decoding against Python standard library."""

  def test_base32_encode(self, msg):
    """Verify base32_encode matches standard library output."""
    result = base32.base32_encode(msg)
    expected = base64.b32encode(msg).decode("ascii")
    assert result == expected, f"Encoding failed for: {msg!r}"

  def test_base32_decode(self, msg):
    """Verify base32_decode correctly decodes encoded data."""
    encoded = base32.base32_encode(msg)
    decoded = base32.base32_decode(encoded)
    assert decoded == msg, f"Decoding failed for: {msg!r}"

  def test_base32_roundtrip(self, msg):
    """Verify encode/decode roundtrip."""
    encoded = base32.base32_encode(msg)
    decoded = base32.base32_decode(encoded)
    assert decoded == msg, f"Roundtrip failed for: {msg!r}"


class TestBase32EdgeCases:
  """Test edge cases and error handling."""

  def test_base32_empty(self):
    """Test empty input."""
    assert base32.base32_encode(b"") == ""
    assert base32.base32_decode("") == b""

  def test_base32_invalid_char(self):
    """Test decoding with invalid characters."""
    with pytest.raises(ValueError, match="Invalid Base32 character"):
      base32.base32_decode("A!BC")

  def test_base32_binary_data(self):
    """Test with various binary data patterns."""
    test_cases = [
      b"\x00" * 10,
      b"\xff" * 10,
      b"\x00\x01\x02\x03\x04\x05",
      bytes(range(256)),
    ]
    for data in test_cases:
      encoded = base32.base32_encode(data)
      decoded = base32.base32_decode(encoded)
      assert decoded == data, f"Failed for binary data: {data!r}"

  def test_base32_padding(self):
    """Test various padding scenarios."""
    # Different lengths produce different padding
    for length in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
      data = b"A" * length
      encoded = base32.base32_encode(data)
      decoded = base32.base32_decode(encoded)
      assert decoded == data, f"Padding failed for length {length}"

  def test_decode_strips_whitespace(self):
    """Test decoding strips leading/trailing whitespace."""
    result = base32.base32_decode("  JBSWY3DP  ")
    assert result == b"Hello"

  def test_decode_only_padding_returns_empty(self):
    """Test decoding only padding characters returns empty bytes."""
    result = base32.base32_decode("========")
    assert result == b""

  def test_decode_without_padding(self):
    """Test decoding without padding characters works correctly."""
    result = base32.base32_decode("JBSWY3DP")
    assert result == b"Hello"

  def test_decode_multiple_invalid_chars(self):
    """Test decoding with multiple invalid characters raises ValueError."""
    with pytest.raises(ValueError, match="Invalid Base32 character"):
      base32.base32_decode("A!@#BC")


class TestBase32Standalone:
  def test_standalone_test_function(self):
    """Call the standalone test_base32 function to cover it."""
    from crypt.encode.base32 import test_base32

    test_base32()
