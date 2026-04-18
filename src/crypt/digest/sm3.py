"""Pure Python implementation of SM3 hash algorithm.

SM3 is a cryptographic hash function standardized by the Chinese
National Cryptography Administration. It produces a 256-bit hash value.

Reference: GM/T 0004-2012 Chinese National Standard
"""

from __future__ import annotations


def left_rotate(value: int, shift_bits: int) -> int:
  """Rotate a 32-bit integer left by shift_bits positions (circular shift).

  Args:
      value: 32-bit integer to rotate
      shift_bits: Number of bits to shift left

  Returns:
      Rotated 32-bit integer
  """
  normalized_shift = shift_bits % 32
  if normalized_shift == 0:
    return value & 0xFFFFFFFF
  return ((value << normalized_shift) | (value >> (32 - normalized_shift))) & 0xFFFFFFFF


# Constants Tj: two different values for different rounds
T = [0x79CC4519 if j < 16 else 0x7A879D8A for j in range(64)]


def ff(x: int, y: int, z: int, j: int) -> int:
  """Boolean function FF for compression round j.

  Args:
      x, y, z: 32-bit integer inputs
      j: Round index (0-63)

  Returns:
      32-bit integer result
  """
  return x ^ y ^ z if j < 16 else (x & y) | (x & z) | (y & z)


def gg(x: int, y: int, z: int, j: int) -> int:
  """Boolean function GG for compression round j.

  Args:
      x, y, z: 32-bit integer inputs
      j: Round index (0-63)

  Returns:
      32-bit integer result
  """
  return x ^ y ^ z if j < 16 else (x & y) | (~x & z)


def p0(x: int) -> int:
  """Permutation function P0."""
  return x ^ left_rotate(x, 9) ^ left_rotate(x, 17)


def p1(x: int) -> int:
  """Permutation function P1."""
  return x ^ left_rotate(x, 15) ^ left_rotate(x, 23)


def padding(message: bytes) -> bytes:
  """Pad message to multiple of 512 bits.

  Args:
      message: Input message bytes

  Returns:
      Padded message
  """
  msg_len = len(message) * 8
  message += b"\x80"
  while (len(message) + 8) % 64 != 0:
    message += b"\x00"
  message += msg_len.to_bytes(8, "big")
  return message


def message_expand(block: bytes) -> tuple[list[int], list[int]]:
  """Expand message block into working variables.

  Args:
      block: 64-byte message block

  Returns:
      Tuple of (W, W') message extension arrays
  """
  w = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
  w.extend(
    p1(w[j - 16] ^ w[j - 9] ^ left_rotate(w[j - 3], 15))
    ^ left_rotate(w[j - 13], 7)
    ^ w[j - 6]
    for j in range(16, 68)
  )
  w_prime = [w[j] ^ w[j + 4] for j in range(64)]
  return w, w_prime


def cf(v: list[int], block: bytes) -> list[int]:
  """Compression function CF.

  Args:
      v: Current state vector (8 x 32-bit words)
      block: 64-byte message block

  Returns:
      New state vector
  """
  a, b, c, d, e, f, g, h = v
  w, w_prime = message_expand(block)

  for j in range(64):
    ss1 = left_rotate(
      (left_rotate(a, 12) + e + left_rotate(T[j], j % 32)) & 0xFFFFFFFF, 7
    )
    ss2 = ss1 ^ left_rotate(a, 12)

    tt1 = (ff(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
    tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF

    d = c
    c = left_rotate(b, 9)
    b = a
    a = tt1
    h = g
    g = left_rotate(f, 19)
    f = e
    e = p0(tt2)

  return [(v[i] ^ x) & 0xFFFFFFFF for i, x in enumerate([a, b, c, d, e, f, g, h])]


def sm3(message: bytes) -> str:
  """Compute SM3 hash of input message.

  Args:
      message: Input message bytes

  Returns:
      64-character hexadecimal hash string (256-bit)

  Example:
      >>> sm3(b"abc")
      '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
  """
  # Initial vector IV
  iv = [
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
  ]

  m = padding(message)
  blocks = [m[i : i + 64] for i in range(0, len(m), 64)]

  v = iv
  for block in blocks:
    v = cf(v, block)

  return "".join(f"{x:08x}" for x in v)
