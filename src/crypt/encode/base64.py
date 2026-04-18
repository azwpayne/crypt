"""Pure Python implementation of Base64 encoding and decoding.

This module provides functions to encode bytes to Base64 strings
and decode Base64 strings back to bytes, following RFC 4648.
"""

B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def base64_encode(data: bytes) -> str:
  """Encode bytes to a Base64 string.

  Args:
      data: The bytes to encode (str will be converted to bytes)

  Returns:
      Base64 encoded string with padding

  Raises:
      TypeError: If input is not bytes or str
  """
  byte_data = bytes(data, "utf-8") if isinstance(data, str) else data

  if not isinstance(byte_data, bytes):
    msg = "Input must be bytes or str"
    raise TypeError(msg)

  if not byte_data:
    return ""

  # Convert input to binary string
  binary_str = "".join(f"{byte:08b}" for byte in byte_data)

  # Group by 6 bits
  groups = [binary_str[i : i + 6] for i in range(0, len(binary_str), 6)]

  # Convert 6-bit groups to characters
  result = [B64_CHARS[int(group.ljust(6, "0"), 2)] for group in groups]

  # Calculate padding needed
  padding = (3 - len(byte_data) % 3) % 3
  result.extend(["="] * padding)

  return "".join(result)


def base64_decode(b64_str: str) -> bytes:
  """Decode a Base64 string to bytes.

  Args:
      b64_str: The Base64 string to decode

  Returns:
      Decoded bytes

  Raises:
      ValueError: If string contains invalid Base64 characters
  """
  if not b64_str:
    return b""

  # Remove padding characters
  b64_str = b64_str.rstrip("=")

  # Convert Base64 characters to indices
  try:
    indices = [B64_CHARS.index(char) for char in b64_str]
  except ValueError as e:
    msg = "Invalid Base64 character found"
    raise ValueError(msg) from e

  # Convert indices to 6-bit binary
  binary_str = "".join(f"{idx:06b}" for idx in indices)

  # Group by 8 bits (bytes)
  byte_groups = [binary_str[i : i + 8] for i in range(0, len(binary_str), 8)]

  # Remove last incomplete byte group if any
  if len(byte_groups[-1]) < 8:
    byte_groups = byte_groups[:-1]

  # Convert binary string to bytes
  return bytes(int(group, 2) for group in byte_groups if len(group) == 8)


if __name__ == "__main__":
  test_cases = [
    b"hello",
    b"World",
    b"Python",
    b"base64",
    b"A",
    b"AB",
    b"ABC",
    b"base64 encode and decode",
    b"",
    b"a" * 100,
  ]

  print(f"当前字符串表: {B64_CHARS}")

  for test in test_cases:
    encoded = base64_encode(test)
    decoded = base64_decode(encoded)
    print(f"原文: {test!r}")
    print(f"编码: {encoded}")
    print(f"解码: {decoded!r}")
    print(f"验证: {test == decoded}\n")
