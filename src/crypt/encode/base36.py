"""Base36 encoding — pure Python implementation.

Base36 uses digits 0-9 and letters a-z (36 characters total).
Commonly used for compact human-readable identifiers.
"""

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
_CHAR_MAP = {c: i for i, c in enumerate(ALPHABET)}
# Also accept uppercase
_CHAR_MAP.update({c.upper(): i for i, c in enumerate(ALPHABET)})


def encode_base36(data: bytes) -> str:
  """Encode *data* bytes to a Base36 string (lowercase)."""
  if not data:
    return "0"
  n_leading = len(data) - len(data.lstrip(b"\x00"))
  num = int.from_bytes(data, "big")
  if num == 0:
    return "0" * len(data)
  digits = []
  while num:
    num, rem = divmod(num, 36)
    digits.append(ALPHABET[rem])
  return "0" * n_leading + "".join(reversed(digits))


def decode_base36(encoded: str) -> bytes:
  """Decode a Base36 string back to bytes."""
  if not encoded:
    return b""
  n_leading = len(encoded) - len(encoded.lstrip("0"))
  remaining = encoded.lstrip("0")
  if not remaining:
    return b"\x00" * n_leading
  num = 0
  for ch in remaining:
    if ch not in _CHAR_MAP:
      msg = f"Invalid Base36 character: {ch!r}"
      raise ValueError(msg)
    num = num * 36 + _CHAR_MAP[ch]
  length = (num.bit_length() + 7) // 8
  return b"\x00" * n_leading + num.to_bytes(length, "big")
