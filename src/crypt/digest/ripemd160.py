"""Pure Python implementation of RIPEMD-160 hash algorithm.

RIPEMD-160 is a cryptographic hash function that produces a 160-bit hash value.
It is similar in structure to MD5 but designed to be more secure.

Reference: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
  from collections.abc import Callable

# RIPEMD-160 initial hash values (IV)
_INITIAL_H: Final[tuple[int, ...]] = (
  0x67452301,
  0xEFCDAB89,
  0x98BADCFE,
  0x10325476,
  0xC3D2E1F0,
)

# Round constants for left lane
_KL: Final[tuple[int, ...]] = (
  0x00000000,  # Rounds 0-15
  0x5A827999,  # Rounds 16-31
  0x6ED9EBA1,  # Rounds 32-47
  0x8F1BBCDC,  # Rounds 48-63
  0xA953FD4E,  # Rounds 64-79
)

# Round constants for right lane
_KR: Final[tuple[int, ...]] = (
  0x50A28BE6,  # Rounds 0-15
  0x5C4DD124,  # Rounds 16-31
  0x6D703EF3,  # Rounds 32-47
  0x7A6D76E9,  # Rounds 48-63
  0x00000000,  # Rounds 64-79
)

# Message word selection for left lane
_RL: Final[tuple[int, ...]] = (
  # Round 1
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
  # Round 2
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
  # Round 3
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
  # Round 4
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
  # Round 5
  4,
  0,
  5,
  9,
  7,
  12,
  2,
  10,
  14,
  1,
  3,
  8,
  11,
  6,
  15,
  13,
)

# Message word selection for right lane
_RR: Final[tuple[int, ...]] = (
  # Round 1
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
  # Round 2
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
  # Round 3
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
  # Round 4
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
  # Round 5
  12,
  15,
  10,
  4,
  1,
  5,
  8,
  7,
  6,
  2,
  13,
  14,
  0,
  3,
  9,
  11,
)

# Rotation amounts for left lane
_SL: Final[tuple[int, ...]] = (
  # Round 1
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
  # Round 2
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
  # Round 3
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
  # Round 4
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
  # Round 5
  9,
  15,
  5,
  11,
  6,
  8,
  13,
  12,
  5,
  12,
  13,
  14,
  11,
  8,
  5,
  6,
)

# Rotation amounts for right lane
_SR: Final[tuple[int, ...]] = (
  # Round 1
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
  # Round 2
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
  # Round 3
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
  # Round 4
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
  # Round 5
  8,
  5,
  12,
  9,
  12,
  5,
  14,
  6,
  8,
  13,
  6,
  5,
  15,
  13,
  11,
  11,
)


def _f1(x: int, y: int, z: int) -> int:
  """Round 1 nonlinear function: x ^ y ^ z."""
  return (x ^ y ^ z) & 0xFFFFFFFF


def _f2(x: int, y: int, z: int) -> int:
  """Round 2 nonlinear function: (x & y) | (~x & z)."""
  return ((x & y) | ((~x) & z)) & 0xFFFFFFFF


def _f3(x: int, y: int, z: int) -> int:
  """Round 3 nonlinear function: (x | ~y) ^ z."""
  return ((x | (~y)) ^ z) & 0xFFFFFFFF


def _f4(x: int, y: int, z: int) -> int:
  """Round 4 nonlinear function: (x & z) | (y & ~z)."""
  return ((x & z) | (y & (~z))) & 0xFFFFFFFF


def _f5(x: int, y: int, z: int) -> int:
  """Round 5 nonlinear function: x ^ (y | ~z)."""
  return (x ^ (y | (~z))) & 0xFFFFFFFF


# Nonlinear functions for left lane (rounds 0-4)
_FUNCTIONS_L: Final[tuple[Callable[[int, int, int], int], ...]] = (
  _f1,
  _f2,
  _f3,
  _f4,
  _f5,
)

# Nonlinear functions for right lane (rounds 4-0, reversed)
_FUNCTIONS_R: Final[tuple[Callable[[int, int, int], int], ...]] = (
  _f5,
  _f4,
  _f3,
  _f2,
  _f1,
)


def _left_rotate(x: int, n: int) -> int:
  """Rotate a 32-bit value left by n bits.

  Args:
      x: 32-bit unsigned integer value
      n: Number of bits to rotate left (0-31)

  Returns:
      Rotated 32-bit value
  """
  return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _process_block(h: list[int], block: bytes) -> None:
  """Process a single 64-byte block.

  Args:
      h: Current hash state (5 x 32-bit words), modified in place
      block: 64-byte data chunk
  """
  # Convert block to 16 x 32-bit words (little-endian)
  x = struct.unpack("<16I", block)

  # Initialize working variables for left and right lines
  # Make copies of the current state
  al, bl, cl, dl, el = h[0], h[1], h[2], h[3], h[4]
  ar, br, cr, dr, er = h[0], h[1], h[2], h[3], h[4]

  # 80 rounds (5 rounds of 16 steps each)
  for j in range(80):
    # Determine round number (0-4)
    round_num = j // 16

    # Left line
    func_l = _FUNCTIONS_L[round_num]
    temp_l = (
      _left_rotate(
        (al + func_l(bl, cl, dl) + x[_RL[j]] + _KL[round_num]) & 0xFFFFFFFF,
        _SL[j],
      )
      + el
    )
    al, bl, cl, dl, el = el, temp_l & 0xFFFFFFFF, bl, _left_rotate(cl, 10), dl

    # Right line
    func_r = _FUNCTIONS_R[round_num]
    temp_r = (
      _left_rotate(
        (ar + func_r(br, cr, dr) + x[_RR[j]] + _KR[round_num]) & 0xFFFFFFFF,
        _SR[j],
      )
      + er
    )
    ar, br, cr, dr, er = er, temp_r & 0xFFFFFFFF, br, _left_rotate(cr, 10), dr

  # Combine results with rotation
  # This is the correct combining step for RIPEMD-160
  t = (h[1] + cl + dr) & 0xFFFFFFFF
  h[1] = (h[2] + dl + er) & 0xFFFFFFFF
  h[2] = (h[3] + el + ar) & 0xFFFFFFFF
  h[3] = (h[4] + al + br) & 0xFFFFFFFF
  h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
  h[0] = t


def _pad_message(message: bytes) -> bytes:
  """Pad message to multiple of 64 bytes.

  RIPEMD-160 padding: append 0x80, then 0x00 bytes until length ≡ 56 (mod 64),
  then append original length as 64-bit little-endian integer.

  Args:
      message: Raw input bytes

  Returns:
      Padded message
  """
  original_length_bits = len(message) * 8
  message += b"\x80"

  # Pad with zeros until length ≡ 56 (mod 64)
  padding_len = (56 - len(message)) % 64
  message += b"\x00" * padding_len

  # Append original length as 64-bit little-endian
  return message + struct.pack("<Q", original_length_bits)


def ripemd160(data: bytes | str) -> str:
  """Compute RIPEMD-160 hash of input data.

  Args:
      data: Input data (bytes or string)

  Returns:
      40-character hexadecimal hash string

  Example:
      >>> ripemd160(b"hello")
      '108f07b8382412612c048d07d13f814118445acd'
      >>> ripemd160("hello")
      '108f07b8382412612c048d07d13f814118445acd'
  """
  message = data if isinstance(data, bytes) else data.encode()

  # Initialize state
  h = list(_INITIAL_H)

  # Pad message
  padded = _pad_message(message)

  # Process each 64-byte block
  for i in range(0, len(padded), 64):
    _process_block(h, padded[i : i + 64])

  # Produce final hash value
  # The state words are in little-endian format; reverse bytes for standard output
  return "".join(
    f"{(word & 0xFF):02x}{((word >> 8) & 0xFF):02x}{((word >> 16) & 0xFF):02x}{((word >> 24) & 0xFF):02x}"
    for word in h
  )


# Backward compatibility alias
hash = ripemd160
