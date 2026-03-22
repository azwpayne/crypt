"""RIPEMD-128 hash function — pure Python implementation.

Produces a 128-bit (16-byte) digest.
Reference: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
"""

import struct

# Round constants
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x00000000]

# Message word selection
_RL = [
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  7,
  4,
  13,
  1,
  10,
  6,
  15,
  3,
  12,
  0,
  9,
  5,
  2,
  14,
  11,
  8,
  3,
  10,
  14,
  4,
  9,
  15,
  8,
  1,
  2,
  7,
  0,
  6,
  13,
  11,
  5,
  12,
  1,
  9,
  11,
  10,
  0,
  8,
  12,
  4,
  13,
  3,
  7,
  15,
  14,
  5,
  6,
  2,
]
_RR = [
  5,
  14,
  7,
  0,
  9,
  2,
  11,
  4,
  13,
  6,
  15,
  8,
  1,
  10,
  3,
  12,
  6,
  11,
  3,
  7,
  0,
  13,
  5,
  10,
  14,
  15,
  8,
  12,
  4,
  9,
  1,
  2,
  15,
  5,
  1,
  3,
  7,
  14,
  6,
  9,
  11,
  8,
  12,
  2,
  10,
  0,
  4,
  13,
  8,
  6,
  4,
  1,
  3,
  11,
  15,
  0,
  5,
  12,
  2,
  13,
  9,
  7,
  10,
  14,
]

# Shift amounts
_SL = [
  11,
  14,
  15,
  12,
  5,
  8,
  7,
  9,
  11,
  13,
  14,
  15,
  6,
  7,
  9,
  8,
  7,
  6,
  8,
  13,
  11,
  9,
  7,
  15,
  7,
  12,
  15,
  9,
  11,
  7,
  13,
  12,
  11,
  13,
  6,
  7,
  14,
  9,
  13,
  15,
  14,
  8,
  13,
  6,
  5,
  12,
  7,
  5,
  11,
  12,
  14,
  15,
  14,
  15,
  9,
  8,
  9,
  14,
  5,
  6,
  8,
  6,
  5,
  12,
]
_SR = [
  8,
  9,
  9,
  11,
  13,
  15,
  15,
  5,
  7,
  7,
  8,
  11,
  14,
  14,
  12,
  6,
  9,
  13,
  15,
  7,
  12,
  8,
  9,
  11,
  7,
  7,
  12,
  7,
  6,
  15,
  13,
  11,
  9,
  7,
  15,
  11,
  8,
  6,
  6,
  14,
  12,
  13,
  5,
  14,
  13,
  13,
  7,
  5,
  15,
  5,
  8,
  11,
  14,
  14,
  6,
  14,
  6,
  9,
  12,
  9,
  12,
  5,
  15,
  8,
]

MASK = 0xFFFFFFFF


def _f(j: int, x: int, y: int, z: int) -> int:
  if j < 16:
    return x ^ y ^ z
  if j < 32:
    return (x & y) | (~x & z)
  if j < 48:
    return (x | ~y) ^ z
  return (x & z) | (y & ~z)


def _rol32(x: int, n: int) -> int:
  return ((x << n) | (x >> (32 - n))) & MASK


def _compress(state: list, block: bytes) -> list:
  words = list(struct.unpack("<16I", block))
  a1, b1, c1, d1 = state
  a2, b2, c2, d2 = state

  for j in range(64):
    round_idx = j // 16
    tmp = (
      _rol32((a1 + _f(j, b1, c1, d1) + words[_RL[j]] + _KL[round_idx]) & MASK, _SL[j])
      & MASK
    )
    a1, b1, c1, d1 = d1, tmp, b1, c1

    tmp = (
      _rol32(
        (a2 + _f(63 - j, b2, c2, d2) + words[_RR[j]] + _KR[round_idx]) & MASK, _SR[j]
      )
      & MASK
    )
    a2, b2, c2, d2 = d2, tmp, b2, c2

  tmp = (state[1] + c1 + d2) & MASK
  return [
    tmp,
    (state[2] + d1 + a2) & MASK,
    (state[3] + a1 + b2) & MASK,
    (state[0] + b1 + c2) & MASK,
  ]


def ripemd128(data: bytes) -> bytes:
  """Compute RIPEMD-128 digest of *data*, returning 16 bytes."""
  # Initial hash values (little-endian)
  state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

  # Pre-processing: padding
  msg = bytearray(data)
  bit_len = len(data) * 8
  msg.append(0x80)
  while len(msg) % 64 != 56:
    msg.append(0)
  msg += struct.pack("<Q", bit_len)

  for i in range(0, len(msg), 64):
    state = _compress(state, bytes(msg[i : i + 64]))

  return struct.pack("<4I", *state)


def ripemd128_hex(data: bytes) -> str:
  """Return RIPEMD-128 digest as a 32-character lowercase hex string."""
  return ripemd128(data).hex()
