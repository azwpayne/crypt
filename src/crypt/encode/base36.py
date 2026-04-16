"""Base36 encoding — pure Python implementation.

Base36 uses digits 0-9 and letters a-z (36 characters total).
Commonly used for compact human-readable identifiers.
"""

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
_CHAR_MAP = {c: i for i, c in enumerate(ALPHABET)}
# Also accept uppercase
_CHAR_MAP.update({c.upper(): i for i, c in enumerate(ALPHABET)})


def base36_encode(num: int) -> str:
  """Encode a non-negative integer to Base36 string."""
  if num < 0:
    msg = "Only non-negative integers are supported"
    raise ValueError(msg)

  if num == 0:
    return "0"

  digits = []
  while num:
    num, rem = divmod(num, 36)
    digits.append(ALPHABET[rem])

  return "".join(reversed(digits))


def base36_decode(encoded: str) -> int:
  """Decode a Base36 string back to an integer."""
  if not encoded:
    return 0

  # Handle leading zeros
  n_leading = len(encoded) - len(encoded.lstrip("0"))
  remaining = encoded.lstrip("0")

  if not remaining:
    return 0

  num = 0
  for ch in remaining:
    if ch not in _CHAR_MAP:
      msg = f"Invalid Base36 character: {ch!r}"
      raise ValueError(msg)
    num = num * 36 + _CHAR_MAP[ch]

  return num


# ... existing code ...


def encode_base36(data: bytes) -> str:
  """Encode bytes to Base36 string.

  Args:
      data: Bytes to encode.

  Returns:
      Base36 encoded string.
  """
  if not data:
    return "0"

  # Count leading zeros
  zero_count = 0
  for b in data:
    if b == 0:
      zero_count += 1
    else:
      break

  # Convert remaining bytes to integer (big-endian)
  if zero_count < len(data):
    num = int.from_bytes(data[zero_count:], byteorder="big")
    encoded = base36_encode(num)
  else:
    encoded = "0"

  # Prepend '0' for each leading zero byte
  return "0" * zero_count + encoded


def decode_base36(encoded: str) -> bytes:
  """Decode Base36 string to bytes.

  Args:
      encoded: Base36 encoded string.

  Returns:
      Decoded bytes.
  """
  if not encoded or encoded == "0":
    return b""

  # Count leading zeros
  zero_count = 0
  for c in encoded:
    if c == "0":
      zero_count += 1
    else:
      break

  # Decode remaining characters
  if zero_count < len(encoded):
    num = base36_decode(encoded[zero_count:])
    if num == 0:
      return b"\x00" * zero_count
    byte_length = (num.bit_length() + 7) // 8
    result = num.to_bytes(byte_length, byteorder="big")
  else:
    # All zeros
    return b"\x00" * zero_count if zero_count > 0 else b""

  # Prepend zero bytes for each leading zero
  return b"\x00" * zero_count + result
