# @author  : azwpayne(https://github.com/azwpayne)
# @name    : html.py
# @time    : 2026/3/18
# @desc    : HTML entity encoding/decoding

"""HTML Entity Encoding

This module provides functions for encoding special characters to HTML entities
and decoding HTML entities back to characters.

Supported entity formats:
- Named entities: &amp;, &lt;, &gt;, &quot;, &apos;, etc.
- Decimal numeric: &#38;, &#60;, etc.
- Hexadecimal numeric: &#x26;, &#x3C;, etc.
"""

import html
import re

# Common HTML5 named entities mapping (subset of most commonly used)
HTML_ENTITIES = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
  "&nbsp;": "\u00a0",
  "&copy;": "\u00a9",
  "&reg;": "\u00ae",
  "&trade;": "\u2122",
  "&euro;": "\u20ac",
  "&pound;": "\u00a3",
  "&yen;": "\u00a5",
  "&cent;": "\u00a2",
  "&sect;": "\u00a7",
  "&para;": "\u00b6",
  "&deg;": "\u00b0",
  "&plusmn;": "\u00b1",
  "&times;": "\u00d7",
  "&divide;": "\u00f7",
  "&frac14;": "\u00bc",
  "&frac12;": "\u00bd",
  "&frac34;": "\u00be",
  "&mdash;": "\u2014",
  "&ndash;": "\u2013",
  "&hellip;": "\u2026",
  "&bull;": "\u2022",
}

# Characters that should be encoded by default (basic HTML escaping)
DEFAULT_ESCAPE_CHARS = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&apos;",
}


def html_encode(text: str, quote: bool = True) -> str:
  """Encode special characters to HTML entities.

  Encodes the characters &, <, and > to their corresponding HTML entities.
  If quote is True, also encodes " and '.

  Args:
      text: The text to encode.
      quote: If True, also encode single and double quotes.

  Returns:
      The HTML-encoded string.

  Examples:
      >>> html_encode("<script>alert('xss')</script>")
      '&lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt;'
      >>> html_encode("Hello & goodbye")
      'Hello &amp; goodbye'
      >>> html_encode('"quoted"', quote=True)
      '&quot;quoted&quot;'
      >>> html_encode('"quoted"', quote=False)
      '"quoted"'
  """
  if not isinstance(text, str):
    msg = "text must be a string"
    raise TypeError(msg)

  # Use Python's built-in html.escape with quote option
  return html.escape(text, quote=quote)


def html_decode(encoded: str) -> str:
  """Decode HTML entities to characters.

      Converts HTML entities (named, decimal, or hexadecimal) back to
  their corresponding characters.

      Args:
          encoded: The HTML-encoded string to decode.

      Returns:
          The decoded string with entities converted to characters.

      Examples:
          >>> html_decode("&lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt;")
          "<script>alert('xss')</script>"
          >>> html_decode("Hello &amp; goodbye")
          'Hello & goodbye'
          >>> html_decode("&#60;div&#62;")  # Decimal
          '<div>'
          >>> html_decode("&#x3C;div&#x3E;")  # Hexadecimal
          '<div>'
  """
  if not isinstance(encoded, str):
    msg = "encoded must be a string"
    raise TypeError(msg)

  # Use Python's built-in html.unescape which handles all entity types
  return html.unescape(encoded)


def encode_all_entities(text: str) -> str:
  """Encode all non-ASCII characters to HTML entities.

  This encodes all characters outside the ASCII range to their
  numeric HTML entities (&#xHHHH; format).

  Args:
      text: The text to encode.

  Returns:
      The string with all non-ASCII characters encoded.

  Examples:
      >>> encode_all_entities("Hello 世界")
      'Hello &#x4e16;&#x754c;'
      >>> encode_all_entities("Café")
      'Caf&#xe9;'
  """
  if not isinstance(text, str):
    msg = "text must be a string"
    raise TypeError(msg)

  result = []
  for char in text:
    code_point = ord(char)
    if code_point > 127:
      # Use hexadecimal entity for non-ASCII
      result.append(f"&#x{code_point:x};")
    elif char in DEFAULT_ESCAPE_CHARS:
      # Use named entity for special HTML chars
      result.append(DEFAULT_ESCAPE_CHARS[char])
    else:
      result.append(char)

  return "".join(result)


def decode_numeric_entities(encoded: str) -> str:
  """Decode only numeric HTML entities (decimal and hexadecimal).

  Unlike html_decode, this function does not decode named entities
  like &amp; or &lt;.

  Args:
      encoded: The string containing numeric entities.

  Returns:
      The string with numeric entities decoded.

  Examples:
      >>> decode_numeric_entities("&#60;div&#62;")
      '<div>'
      >>> decode_numeric_entities("&#x3C;div&#x3E;")
      '<div>'
      >>> decode_numeric_entities("&amp; remains")
      '&amp; remains'
  """
  if not isinstance(encoded, str):
    msg = "encoded must be a string"
    raise TypeError(msg)

  def replace_entity(match: re.Match) -> str:
    entity = match.group(0)

    # Hexadecimal entity
    if entity.startswith(("&#x", "&#X")):
      try:
        code_point = int(entity[3:-1], 16)
        return chr(code_point)
      except (ValueError, OverflowError):
        return entity

    # Decimal entity
    if entity.startswith("&#"):
      try:
        code_point = int(entity[2:-1])
        return chr(code_point)
      except (ValueError, OverflowError):
        return entity

    return entity

  # Pattern for numeric entities
  pattern = r"&#(?:x|X)?[0-9a-fA-F]+;"
  return re.sub(pattern, replace_entity, encoded)


def strip_tags(html_text: str) -> str:
  """Remove HTML tags from text.

  Args:
      html_text: The HTML text to strip tags from.

  Returns:
      The text with HTML tags removed.

  Examples:
      >>> strip_tags("<p>Hello <b>world</b></p>")
      'Hello world'
      >>> strip_tags("<script>alert('xss')</script>Text")
      "alert('xss')Text"
  """
  if not isinstance(html_text, str):
    msg = "html_text must be a string"
    raise TypeError(msg)

  # Remove HTML tags using regex
  return re.sub(r"<[^>]+>", "", html_text)
