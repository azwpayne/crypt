# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_url.py
# @time    : 2026/3/18
# @desc    : Tests for URL percent-encoding/decoding
import urllib.parse
from crypt.encode.url import url_decode, url_encode

import pytest

from tests import BYTE_TEST_CASES


@pytest.mark.parametrize("msg", BYTE_TEST_CASES)
class TestUrlEncoding:
  """Test URL encoding and decoding against Python standard library."""

  def test_url_encode_matches_stdlib(self, msg):
    """Verify url_encode matches urllib.parse.quote output."""
    result = url_encode(msg)
    expected = urllib.parse.quote(msg, safe="")
    assert result == expected, f"Encoding failed for: {msg!r}"

  def test_url_decode_matches_stdlib(self, msg):
    """Verify url_decode correctly decodes urllib.parse.quote output."""
    encoded = urllib.parse.quote(msg, safe="")
    decoded = url_decode(encoded)
    assert decoded == msg, f"Decoding failed for: {msg!r}"

  def test_url_roundtrip(self, msg):
    """Verify encode/decode roundtrip."""
    encoded = url_encode(msg)
    decoded = url_decode(encoded)
    assert decoded == msg, f"Roundtrip failed for: {msg!r}"


class TestUrlEdgeCases:
  """Test edge cases and error handling."""

  def test_url_empty(self):
    """Test empty input."""
    assert url_encode(b"") == ""
    assert url_encode("") == ""
    assert url_decode("") == b""

  def test_url_safe_characters(self):
    """Test safe character handling."""
    # Test default safe chars (unreserved)
    assert url_encode("abcABC123-_.~") == "abcABC123-_.~"

    # Test custom safe chars
    assert url_encode("hello world", safe=" ") == "hello world"
    assert url_encode("path/to/file", safe="/") == "path/to/file"
    assert url_encode("a@b.com", safe="@.") == "a@b.com"

    # Compare with urllib
    assert url_encode("hello world", safe=" ") == urllib.parse.quote(
      "hello world", safe=" "
    )

  def test_url_space_encoding(self):
    """Test that spaces are encoded as %20, not +."""
    assert "%20" in url_encode("hello world")
    assert "+" not in url_encode("hello world")

  def test_url_binary_data(self):
    """Test with various binary data patterns."""
    test_cases = [
      b"\x00" * 10,
      b"\xff" * 10,
      b"\x00\x01\x02\x03\x04\x05",
      bytes(range(256)),
    ]
    for data in test_cases:
      encoded = url_encode(data)
      decoded = url_decode(encoded)
      assert decoded == data, f"Failed for binary data: {data!r}"

  def test_url_unicode(self):
    """Test Unicode handling."""
    test_cases = [
      "Hello, 世界",
      "Café",
      "🚀 rocket",
      "日本語テキスト",
    ]
    for text in test_cases:
      encoded = url_encode(text)
      decoded = url_decode(encoded)
      assert decoded == text.encode("utf-8"), f"Failed for: {text!r}"

  def test_url_decode_invalid_percent(self):
    """Test decoding invalid percent sequences."""
    # Incomplete percent sequence
    with pytest.raises(ValueError, match="Incomplete percent-encoding"):
      url_decode("hello%2")

    # Invalid hex digits
    with pytest.raises(ValueError, match="Invalid percent-encoding"):
      url_decode("hello%ZZ")

    with pytest.raises(ValueError, match="Invalid percent-encoding"):
      url_decode("hello%G1")

  def test_url_decode_case_insensitive(self):
    """Test that percent decoding is case-insensitive."""
    assert url_decode("%2f") == b"/"
    assert url_decode("%2F") == b"/"
    assert url_decode("%aa") == b"\xaa"
    assert url_decode("%AA") == b"\xaa"

  def test_url_type_errors(self):
    """Test type validation."""
    with pytest.raises(TypeError):
      url_encode(123)

    with pytest.raises(TypeError):
      url_encode(None)

  def test_url_all_ascii_chars(self):
    """Test encoding all ASCII characters."""
    for i in range(128):
      char = chr(i)
      encoded = url_encode(char)
      decoded = url_decode(encoded)
      assert decoded == char.encode("utf-8"), f"Failed for ASCII {i!r}"


class TestUrlRfc3986:
  """Test RFC 3986 compliance."""

  def test_unreserved_chars_never_encoded(self):
    """Test that unreserved chars are never encoded per RFC 3986."""
    unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
    assert url_encode(unreserved) == unreserved

  def test_reserved_chars_encoded(self):
    """Test that reserved chars are encoded."""
    reserved = ":/?#[]@!$&'()*+,;="
    encoded = url_encode(reserved)
    assert "%" in encoded
    for char in reserved:
      assert char not in encoded
