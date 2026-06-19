# @author  : azwpayne(https://github.com/azwpayne)
# @name    : siphash.py
# @time    : 2026/03/30
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : SipHash-2-4 pseudorandom function (Aumasson & Bernstein, 2012)
"""
SipHash-2-4 is a fast pseudorandom function (keyed hash) designed by
Jean-Philippe Aumasson and Daniel J. Bernstein in 2012.

It is optimized for short messages and is used in hash tables, networking
(e.g. IPv6 flow labels), and as a MAC.  SipHash-2-4 uses 2 compression
rounds and 4 finalization rounds, producing a 64-bit (8-byte) tag.

Reference: https://131002.net/siphash/siphash.pdf
"""

_MASK64: int = (1 << 64) - 1


def _rotl(x: int, b: int) -> int:
  """Rotate 64-bit integer x left by b bits."""
  return ((x << b) | (x >> (64 - b))) & _MASK64


def _sipround(v0: int, v1: int, v2: int, v3: int) -> tuple[int, int, int, int]:
  """Perform one SipRound on the 4x64-bit state."""
  v0 = (v0 + v1) & _MASK64
  v1 = _rotl(v1, 13) ^ v0
  v0 = _rotl(v0, 32)
  v2 = (v2 + v3) & _MASK64
  v3 = _rotl(v3, 16) ^ v2
  v0 = (v0 + v3) & _MASK64
  v3 = _rotl(v3, 21) ^ v0
  v2 = (v2 + v1) & _MASK64
  v1 = _rotl(v1, 17) ^ v2
  v2 = _rotl(v2, 32)
  return v0, v1, v2, v3


def siphash24(key: bytes, message: bytes) -> bytes:
  """
  Compute SipHash-2-4 for a message, returning an 8-byte tag.

  Args:
      key: 16-byte secret key.
      message: Arbitrary-length message to hash.

  Returns:
      8-byte authentication tag (little-endian).

  Raises:
      ValueError: If key is not exactly 16 bytes.
  """
  if len(key) != 16:
    msg = f"Key must be 16 bytes, got {len(key)}"
    raise ValueError(msg)

  k0: int = int.from_bytes(key[:8], "little")
  k1: int = int.from_bytes(key[8:], "little")

  # Initialization
  v0: int = k0 ^ 0x736F6D6570736575
  v1: int = k1 ^ 0x646F72616E646F6D
  v2: int = k0 ^ 0x6C7967656E657261
  v3: int = k1 ^ 0x7465646279746573

  msg_len: int = len(message)

  # Process full 8-byte blocks
  i = 0
  while i + 8 <= msg_len:
    m: int = int.from_bytes(message[i : i + 8], "little")
    v3 ^= m
    # 2 compression rounds
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0 ^= m
    i += 8

  # Pack remaining bytes + length into last 8-byte word
  b: int = msg_len << 56
  remaining: int = msg_len - i
  for j in range(remaining):
    b |= message[i + j] << (j * 8)

  v3 ^= b
  # 2 compression rounds
  v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
  v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
  v0 ^= b

  # Finalization
  v2 ^= 0xFF
  # 4 finalization rounds
  v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
  v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
  v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
  v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)

  result: int = v0 ^ v1 ^ v2 ^ v3
  return result.to_bytes(8, "little")


def siphash24_int(key: bytes, message: bytes) -> int:
  """
  Compute SipHash-2-4 for a message, returning a 64-bit integer.

  Args:
      key: 16-byte secret key.
      message: Arbitrary-length message to hash.

  Returns:
      64-bit unsigned integer tag.

  Raises:
      ValueError: If key is not exactly 16 bytes.
  """
  return int.from_bytes(siphash24(key, message), "little")
