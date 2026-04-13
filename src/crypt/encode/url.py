# @author  : azwpayne(https://github.com/azwpayne)
# @name    : url.py
# @time    : 2026/3/18
# @desc    : URL percent-encoding (RFC 3986)

# RFC 3986 unreserved characters that never need encoding
UNRESERVED_CHARS = frozenset(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)

# Hex digits for percent encoding
HEX_DIGITS = "0123456789ABCDEF"


def url_encode(data: object, safe: str = "") -> str:
  """
  Encode bytes or string to URL percent-encoded string per RFC 3986.

  Alphanumeric characters, hyphen, period, underscore, and tilde
  are never encoded. Additional characters can be specified as safe.

  Spaces are encoded as %20 (not +) for strict RFC compliance.

  Args:
      data: The data to encode. If str, it is first encoded to UTF-8 bytes.
      safe: Additional characters that should not be encoded.

  Returns:
      The percent-encoded string.

  Raises:
      TypeError: If data is not bytes or str.

  Examples:
      >>> url_encode("hello world")
      'hello%20world'
      >>> url_encode("hello world", safe=" ")
      'hello world'
      >>> url_encode("path/to/file")
      'path%2Fto%2Ffile'
      >>> url_encode("path/to/file", safe="/")
      'path/to/file'
      >>> url_encode(b"\x00\x01\x02")
      '%00%01%02'
  """
  match data:
    case str():
      byte_data = data.encode("utf-8")
    case bytes():
      byte_data = data
    case _:
      msg = "data must be bytes or str"
      raise TypeError(msg)

  # Build set of characters that don't need encoding
  safe_chars = UNRESERVED_CHARS | frozenset(safe)

  result = []
  for byte in byte_data:
    char = chr(byte)
    if char in safe_chars:
      result.append(char)
    else:
      # Percent-encode: %XX
      result.append("%")
      result.append(HEX_DIGITS[byte >> 4])  # high nibble
      result.append(HEX_DIGITS[byte & 0x0F])  # low nibble

  return "".join(result)


def url_decode(encoded: str) -> bytes:
  """
  Decode a URL percent-encoded string to bytes per RFC 3986.

  Args:
      encoded: The percent-encoded string to decode.

  Returns:
      The decoded bytes.

  Raises:
      ValueError: If the encoded string contains invalid percent-encoding
          (e.g., incomplete % sequence or non-hex digits).

  Examples:
      >>> url_decode("hello%20world")
      b'hello world'
      >>> url_decode("path%2Fto%2Ffile")
      b'path/to/file'
      >>> url_decode("%00%01%02")
      b'\\x00\\x01\\x02'
      >>> url_decode("")
      b''
  """
  if not encoded:
    return b""

  result = bytearray()
  i = 0
  length = len(encoded)

  while i < length:
    char = encoded[i]

    if char == "%":
      # Need at least 2 more characters for valid %XX
      if i + 2 >= length:
        msg = f"Incomplete percent-encoding at position {i}"
        raise ValueError(msg)

      hex_chars = encoded[i + 1 : i + 3]

      try:
        byte_value = int(hex_chars, 16)
      except ValueError as e:
        msg = f"Invalid percent-encoding '%{hex_chars}' at position {i}"
        raise ValueError(msg) from e

      result.append(byte_value)
      i += 3
    else:
      # Regular character - encode to UTF-8 bytes
      result.extend(char.encode("utf-8"))
      i += 1

  return bytes(result)
