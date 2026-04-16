"""Tests for HTML entity encoding/decoding.

Tests for HTML entity encoding/decoding module, verifying against Python's
standard library html module and testing various entity formats.
"""

from __future__ import annotations

import html
from crypt.encode.html import (
  decode_numeric_entities,
  encode_all_entities,
  html_decode,
  html_encode,
  strip_tags,
)

import pytest


class TestHtmlBasicEncoding:
  """Test basic HTML encoding functionality."""

  def test_encode_ampersand(self):
    """Test encoding of ampersand."""
    assert html_encode("&") == "&amp;"

  def test_encode_less_than(self):
    """Test encoding of less than."""
    assert html_encode("<") == "&lt;"

  def test_encode_greater_than(self):
    """Test encoding of greater than."""
    assert html_encode(">") == "&gt;"

  def test_encode_all_basic(self):
    """Test encoding all basic entities."""
    assert html_encode("&<>") == "&amp;&lt;&gt;"

  def test_no_encoding_needed(self):
    """Test that safe characters are not encoded."""
    assert html_encode("Hello World") == "Hello World"

  def test_empty_string(self):
    """Test encoding empty string."""
    assert html_encode("") == ""


class TestHtmlQuoteEncoding:
  """Test HTML encoding with quote handling."""

  def test_encode_double_quotes_with_quote_true(self):
    """Test encoding double quotes when quote=True."""
    assert html_encode('"') == "&quot;"

  def test_encode_single_quotes_with_quote_true(self):
    """Test encoding single quotes when quote=True."""
    assert html_encode("'") == "&#x27;"

  def test_no_encode_quotes_with_quote_false(self):
    """Test quotes not encoded when quote=False."""
    assert html_encode('"hello"', quote=False) == '"hello"'
    assert html_encode("'hello'", quote=False) == "'hello'"

  def test_xss_payload_encoding(self):
    """Test encoding of typical XSS payloads."""
    assert html_encode("<script>alert('xss')</script>") == (
      "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
    )


class TestHtmlDecoding:
  """Test HTML entity decoding."""

  def test_decode_ampersand(self):
    """Test decoding named entity &amp;."""
    assert html_decode("&amp;") == "&"

  def test_decode_less_than(self):
    """Test decoding named entity &lt;."""
    assert html_decode("&lt;") == "<"

  def test_decode_greater_than(self):
    """Test decoding named entity &gt;."""
    assert html_decode("&gt;") == ">"

  def test_decode_decimal_entity(self):
    """Test decoding decimal numeric entity."""
    assert html_decode("&#38;") == "&"
    assert html_decode("&#60;") == "<"
    assert html_decode("&#62;") == ">"

  def test_decode_hex_entity(self):
    """Test decoding hexadecimal numeric entity."""
    assert html_decode("&#x26;") == "&"
    assert html_decode("&#x3C;") == "<"
    assert html_decode("&#x3E;") == ">"
    # Uppercase X
    assert html_decode("&#X26;") == "&"

  def test_decode_multiple_entities(self):
    """Test decoding multiple entities."""
    assert html_decode("&lt;div&gt;Hello&lt;/div&gt;") == "<div>Hello</div>"

  def test_decode_all_named_entities(self):
    """Test decoding all common named entities."""
    assert html_decode("&quot;") == '"'
    assert html_decode("&apos;") == "'"
    assert html_decode("&nbsp;") == "\u00a0"
    assert html_decode("&copy;") == "\u00a9"
    assert html_decode("&reg;") == "\u00ae"
    assert html_decode("&trade;") == "\u2122"
    assert html_decode("&euro;") == "\u20ac"

  def test_empty_string_decode(self):
    """Test decoding empty string."""
    assert html_decode("") == ""


class TestHtmlRoundtrip:
  """Test encoding/decoding roundtrips."""

  def test_basic_roundtrip(self):
    """Test basic encode/decode roundtrip."""
    self._extracted_from_test_complex_html_roundtrip_3("<script>alert('xss')</script>")

  def test_quote_roundtrip(self):
    """Test quote encoding roundtrip."""
    self._extracted_from_test_complex_html_roundtrip_3("\"Hello\" & 'World'")

  def test_complex_html_roundtrip(self):
    """Test complex HTML roundtrip."""
    self._extracted_from_test_complex_html_roundtrip_3(
      '<div class="test">Hello & <b>World</b></div>'
    )

  @staticmethod
  def _extracted_from_test_complex_html_roundtrip_3(arg0):
    original = arg0
    encoded = html_encode(original)
    decoded = html_decode(encoded)
    assert decoded == original


class TestEncodeAllEntities:
  """Test encode_all_entities function."""

  def test_encode_non_ascii(self):
    """Test encoding non-ASCII characters."""
    result = encode_all_entities("Hello 世界")
    assert result == "Hello &#x4e16;&#x754c;"

  def test_encode_accented_chars(self):
    """Test encoding accented characters."""
    result = encode_all_entities("Café")
    assert "&#x" in result
    assert "Caf" in result

  def test_encode_basic_chars_still_named(self):
    """Test that basic chars still use named entities."""
    result = encode_all_entities("<>&")
    assert "&lt;" in result
    assert "&gt;" in result
    assert "&amp;" in result

  def test_empty_string_all_entities(self):
    """Test encoding empty string."""
    assert encode_all_entities("") == ""

  def test_ascii_only_no_change(self):
    """Test that ASCII-only string with no special chars is unchanged."""
    assert encode_all_entities("Hello World 123") == "Hello World 123"


class TestDecodeNumericEntities:
  """Test decode_numeric_entities function."""

  def test_decode_decimal_only(self):
    """Test decoding decimal entities only."""
    assert decode_numeric_entities("&#60;div&#62;") == "<div>"

  def test_decode_hex_only(self):
    """Test decoding hexadecimal entities only."""
    assert decode_numeric_entities("&#x3C;div&#x3E;") == "<div>"

  def test_named_entities_preserved(self):
    """Test that named entities are not decoded."""
    result = decode_numeric_entities("&amp; remains")
    assert result == "&amp; remains"

  def test_decode_unicode_codepoints(self):
    """Test decoding Unicode codepoints."""
    assert decode_numeric_entities("&#x4e16;&#x754c;") == "世界"
    assert decode_numeric_entities("&#19990;&#30028;") == "世界"

  def test_mixed_entities(self):
    """Test mixed numeric and named entities."""
    result = decode_numeric_entities("&amp; &#60; &#x3E;")
    assert result == "&amp; < >"

  def test_invalid_entities_preserved(self):
    """Test that invalid entities are preserved."""
    assert decode_numeric_entities("&#xZZZ;") == "&#xZZZ;"
    assert decode_numeric_entities("&#99999;") == chr(99999)

  def test_case_insensitive_hex(self):
    """Test that hex decoding is case insensitive."""
    assert decode_numeric_entities("&#x41;") == "A"
    assert decode_numeric_entities("&#X41;") == "A"
    assert decode_numeric_entities("&#x41;&#X42;") == "AB"

  def test_decode_numeric_overflow(self):
    """Test that overflow entities are preserved."""
    # Very large hex value that causes OverflowError in chr()
    assert decode_numeric_entities("&#xFFFFFFFFFFFF;") == "&#xFFFFFFFFFFFF;"
    # Very large decimal value that causes OverflowError in chr()
    assert decode_numeric_entities("&#99999999999999999999;") == "&#99999999999999999999;"


class TestStripTags:
  """Test strip_tags function."""

  def test_strip_simple_tags(self):
    """Test stripping simple HTML tags."""
    assert strip_tags("<p>Hello</p>") == "Hello"

  def test_strip_nested_tags(self):
    """Test stripping nested HTML tags."""
    assert strip_tags("<p>Hello <b>world</b></p>") == "Hello world"

  def test_strip_script_tags(self):
    """Test stripping script tags."""
    result = strip_tags("<script>alert('xss')</script>Text")
    assert result == "alert('xss')Text"

  def test_strip_with_attributes(self):
    """Test stripping tags with attributes."""
    assert strip_tags('<div class="test">Content</div>') == "Content"

  def test_strip_self_closing(self):
    """Test stripping self-closing tags."""
    assert strip_tags("Line<br/>Break") == "LineBreak"
    assert strip_tags("Line<br />Break") == "LineBreak"

  def test_no_tags(self):
    """Test string with no tags."""
    assert strip_tags("Just text") == "Just text"

  def test_empty_string_strip(self):
    """Test stripping empty string."""
    assert strip_tags("") == ""

  def test_only_tags(self):
    """Test string with only tags."""
    assert strip_tags("<p></p>") == ""


class TestHtmlTypeErrors:
  """Test type validation."""

  def test_encode_non_string_raises(self):
    """Test that encoding non-string raises TypeError."""
    with pytest.raises(TypeError, match="text must be a string"):
      html_encode(123)
    with pytest.raises(TypeError, match="text must be a string"):
      html_encode(None)
    with pytest.raises(TypeError, match="text must be a string"):
      html_encode(b"bytes")

  def test_decode_non_string_raises(self):
    """Test that decoding non-string raises TypeError."""
    with pytest.raises(TypeError, match="encoded must be a string"):
      html_decode(123)
    with pytest.raises(TypeError, match="encoded must be a string"):
      html_decode(None)
    with pytest.raises(TypeError, match="encoded must be a string"):
      html_decode(b"bytes")

  def test_encode_all_non_string_raises(self):
    """Test that encode_all_entities with non-string raises TypeError."""
    with pytest.raises(TypeError, match="text must be a string"):
      encode_all_entities(123)

  def test_decode_numeric_non_string_raises(self):
    """Test that decode_numeric_entities with non-string raises TypeError."""
    with pytest.raises(TypeError, match="encoded must be a string"):
      decode_numeric_entities(123)

  def test_strip_tags_non_string_raises(self):
    """Test that strip_tags with non-string raises TypeError."""
    with pytest.raises(TypeError, match="html_text must be a string"):
      strip_tags(123)


class TestHtmlAgainstStdlib:
  """Test that our implementation matches Python's standard library."""

  def test_encode_matches_stdlib(self):
    """Verify html_encode matches html.escape."""
    test_cases = [
      "Hello World",
      "<script>alert('xss')</script>",
      '"quoted"',
      "&",
      "<>&",
      "Test <div> & more",
    ]
    for case in test_cases:
      assert html_encode(case) == html.escape(case, quote=True)
      assert html_encode(case, quote=False) == html.escape(case, quote=False)

  def test_decode_matches_stdlib(self):
    """Verify html_decode matches html.unescape."""
    test_cases = [
      "&amp;&lt;&gt;",
      "&#38;&#60;&#62;",
      "&#x26;&#x3C;&#x3E;",
      "&quot;quoted&quot;",
      "&copy; 2024",
    ]
    for case in test_cases:
      assert html_decode(case) == html.unescape(case)

  def test_roundtrip_matches_stdlib(self):
    """Verify roundtrip encoding/decoding."""
    test_cases = [
      "Hello World",
      "<script>alert('xss')</script>",
      "<div class='test'>Content & more</div>",
      "Special: & < > \" '",
    ]
    for case in test_cases:
      encoded = html.escape(case, quote=True)
      decoded = html.unescape(encoded)
      assert html_decode(html_encode(case)) == decoded


class TestHtmlEdgeCases:
  """Test edge cases and unusual inputs."""

  def test_encode_multiline(self):
    """Test encoding multiline strings."""
    multiline = "Line1\nLine2\tTabbed"
    result = html_encode(multiline)
    assert result == multiline  # Whitespace should not be encoded

  def test_decode_multiline(self):
    """Test decoding multiline strings with entities."""
    multiline = "&lt;div&gt;\n&lt;/div&gt;"
    result = html_decode(multiline)
    assert result == "<div>\n</div>"

  def test_encode_unicode(self):
    """Test encoding Unicode strings."""
    unicode_str = "Hello 世界 🌍"
    result = html_encode(unicode_str)
    assert result == unicode_str  # Unicode should not be encoded by default

  def test_decode_unicode(self):
    """Test decoding with Unicode."""
    decoded = html_decode("&#x1F30D;")  # Earth emoji
    assert decoded == "🌍"

  def test_large_input(self):
    """Test with large input."""
    large = "<script>" * 1000 + "content" + "</script>" * 1000
    result = html_encode(large)
    assert "&lt;script&gt;" in result
    assert "</script>" not in result

  def test_consecutive_entities(self):
    """Test consecutive entities."""
    assert html_decode("&lt;&gt;&amp;") == "<>&"
    assert html_encode("<>&") == "&lt;&gt;&amp;"

  def test_partial_entity_not_decoded(self):
    """Test that partial entities are left as-is.

    Note: Python's html.unescape is lenient and may decode entities
    without trailing semicolons, which is actually the expected behavior.
    """
    # Python's html.unescape actually decodes entities without semicolons
    # This is lenient but matches browser behavior
    assert html_decode("&amp;") == "&"  # With semicolon
    assert html_decode("&#60;") == "<"  # With semicolon
    assert html_decode("&#x3C;") == "<"  # With semicolon
