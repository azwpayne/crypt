"""Pure Python implementation of the MD4 hash algorithm.

MD4 (Message-Digest Algorithm 4) produces a 128-bit hash value from input data.
Designed by Ron Rivest in 1990. MD5 was designed as an improved version of MD4.
Note: MD4 is cryptographically broken and should not be used for security.
This implementation is for educational purposes only.

Reference: RFC 1320
"""

from __future__ import annotations

import struct
from typing import Final

# MD4 initial hash values (IV) - little-endian
_INITIAL_A: Final = 0x67452301
_INITIAL_B: Final = 0xEFCDAB89
_INITIAL_C: Final = 0x98BADCFE
_INITIAL_D: Final = 0x10325476


def _left_rotate(x: int, amount: int) -> int:
  """Rotate a 32-bit value left by the specified amount."""
  return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


def _f(x: int, y: int, z: int) -> int:
  """Round 1 function: (x & y) | (~x & z)"""
  return (x & y) | ((~x) & z)


def _g(x: int, y: int, z: int) -> int:
  """Round 2 function: (x & y) | (x & z) | (y & z)"""
  return (x & y) | (x & z) | (y & z)


def _h(x: int, y: int, z: int) -> int:
  """Round 3 function: x ^ y ^ z"""
  return x ^ y ^ z


def _process_chunk(state: list[int], chunk: bytes) -> None:
  """Process a single 64-byte chunk."""
  # Unpack chunk into 16 32-bit words (little-endian)
  words = list(struct.unpack("<16I", chunk))

  # Save current state
  a, b, c, d = state

  # Round 1
  for i in range(16):
    k = i
    s = [3, 7, 11, 19][i % 4]
    temp = (_f(b, c, d) + a + words[k]) & 0xFFFFFFFF
    a, b, c, d = d, _left_rotate(temp, s), b, c

  # Round 2
  for i in range(16):
    k = (i // 4) + (i % 4) * 4
    s = [3, 5, 9, 13][i % 4]
    temp = (_g(b, c, d) + a + words[k] + 0x5A827999) & 0xFFFFFFFF
    a, b, c, d = d, _left_rotate(temp, s), b, c

  # Round 3
  for i in range(16):
    k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][i]
    s = [3, 9, 11, 15][i % 4]
    temp = (_h(b, c, d) + a + words[k] + 0x6ED9EBA1) & 0xFFFFFFFF
    a, b, c, d = d, _left_rotate(temp, s), b, c

  # Update state
  state[0] = (state[0] + a) & 0xFFFFFFFF
  state[1] = (state[1] + b) & 0xFFFFFFFF
  state[2] = (state[2] + c) & 0xFFFFFFFF
  state[3] = (state[3] + d) & 0xFFFFFFFF


def _pad_message(message: bytes) -> bytes:
  """Pad message to multiple of 64 bytes."""
  original_length_bits = len(message) * 8

  # Append 0x80
  message += b"\x80"

  # Pad with zeros until length ≡ 56 (mod 64)
  padding_len = (56 - len(message)) % 64
  message += b"\x00" * padding_len

  # Append original length as 64-bit little-endian
  return message + struct.pack("<Q", original_length_bits)


def md4(data: bytes | str) -> str:
  """Compute MD4 hash of input data.

  Args:
      data: Input data (bytes or string)

  Returns:
      32-character hexadecimal hash string

  Example:
      >>> md4(b"hello")
      '866437cb7a794bce2b727acc0362ee27'
  """
  message = data if isinstance(data, bytes) else data.encode()

  # Initialize state
  state = [_INITIAL_A, _INITIAL_B, _INITIAL_C, _INITIAL_D]

  # Pad message
  padded = _pad_message(message)

  # Process each 64-byte chunk
  for i in range(0, len(padded), 64):
    _process_chunk(state, padded[i : i + 64])

  # Return hash as hex string
  return struct.pack("<4I", *state).hex()
