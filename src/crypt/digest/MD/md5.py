"""Pure Python implementation of the MD5 hash algorithm.

MD5 (Message-Digest Algorithm 5) produces a 128-bit hash value from input data.
Note: MD5 is cryptographically broken and should not be used for security purposes.
This implementation is for educational purposes only.

Reference: RFC 1321
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
  from collections.abc import Callable

# MD5 initial hash values (IV) - little-endian
_INITIAL_A: Final = 0x67452301
_INITIAL_B: Final = 0xEFCDAB89
_INITIAL_C: Final = 0x98BADCFE
_INITIAL_D: Final = 0x10325476

# MD5 round constants (K values) - integer part of abs(sin(i+1)) * 2^32
_K: Final[tuple[int, ...]] = (
  0xD76AA478,
  0xE8C7B756,
  0x242070DB,
  0xC1BDCEEE,
  0xF57C0FAF,
  0x4787C62A,
  0xA8304613,
  0xFD469501,
  0x698098D8,
  0x8B44F7AF,
  0xFFFF5BB1,
  0x895CD7BE,
  0x6B901122,
  0xFD987193,
  0xA679438E,
  0x49B40821,
  0xF61E2562,
  0xC040B340,
  0x265E5A51,
  0xE9B6C7AA,
  0xD62F105D,
  0x02441453,
  0xD8A1E681,
  0xE7D3FBC8,
  0x21E1CDE6,
  0xC33707D6,
  0xF4D50D87,
  0x455A14ED,
  0xA9E3E905,
  0xFCEFA3F8,
  0x676F02D9,
  0x8D2A4C8A,
  0xFFFA3942,
  0x8771F681,
  0x6D9D6122,
  0xFDE5380C,
  0xA4BEEA44,
  0x4BDECFA9,
  0xF6BB4B60,
  0xBEBFBC70,
  0x289B7EC6,
  0xEAA127FA,
  0xD4EF3085,
  0x04881D05,
  0xD9D4D039,
  0xE6DB99E5,
  0x1FA27CF8,
  0xC4AC5665,
  0xF4292244,
  0x432AFF97,
  0xAB9423A7,
  0xFC93A039,
  0x655B59C3,
  0x8F0CCC92,
  0xFFEFF47D,
  0x85845DD1,
  0x6FA87E4F,
  0xFE2CE6E0,
  0xA3014314,
  0x4E0811A1,
  0xF7537E82,
  0xBD3AF235,
  0x2AD7D2BB,
  0xEB86D391,
)

# Shift amounts for each round
_SHIFTS: Final[tuple[int, ...]] = (
  # Round 1
  7,
  12,
  17,
  22,
  7,
  12,
  17,
  22,
  7,
  12,
  17,
  22,
  7,
  12,
  17,
  22,
  # Round 2
  5,
  9,
  14,
  20,
  5,
  9,
  14,
  20,
  5,
  9,
  14,
  20,
  5,
  9,
  14,
  20,
  # Round 3
  4,
  11,
  16,
  23,
  4,
  11,
  16,
  23,
  4,
  11,
  16,
  23,
  4,
  11,
  16,
  23,
  # Round 4
  6,
  10,
  15,
  21,
  6,
  10,
  15,
  21,
  6,
  10,
  15,
  21,
  6,
  10,
  15,
  21,
)

# Word indices for each round
_INDICES: Final[tuple[int, ...]] = (
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
  1,
  6,
  11,
  0,
  5,
  10,
  15,
  4,
  9,
  14,
  3,
  8,
  13,
  2,
  7,
  12,
  # Round 3
  5,
  8,
  11,
  14,
  1,
  4,
  7,
  10,
  13,
  0,
  3,
  6,
  9,
  12,
  15,
  2,
  # Round 4
  0,
  7,
  14,
  5,
  12,
  3,
  10,
  1,
  8,
  15,
  6,
  13,
  4,
  11,
  2,
  9,
)

# Round boundaries for function selection
_ROUND1_END: Final = 16
_ROUND2_END: Final = 32
_ROUND3_END: Final = 48


@dataclass(slots=True)
class _MD5State:
  """Internal MD5 state (4 32-bit registers)."""

  a: int
  b: int
  c: int
  d: int

  def copy(self) -> _MD5State:
    """Create a copy of the state."""
    return _MD5State(self.a, self.b, self.c, self.d)

  def add(self, other: _MD5State) -> None:
    """Add another state to this one (mod 2^32)."""
    self.a = (self.a + other.a) & 0xFFFFFFFF
    self.b = (self.b + other.b) & 0xFFFFFFFF
    self.c = (self.c + other.c) & 0xFFFFFFFF
    self.d = (self.d + other.d) & 0xFFFFFFFF

  def to_bytes(self) -> bytes:
    """Convert state to little-endian bytes."""
    return struct.pack("<4I", self.a, self.b, self.c, self.d)


def _left_rotate(x: int, amount: int) -> int:
  """Rotate a 32-bit value left by the specified amount.

  Args:
      x: 32-bit unsigned integer value
      amount: Number of bits to rotate left (0-31)

  Returns:
      Rotated 32-bit value
  """
  return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


def _choice(mask: int, if_true: int, if_false: int) -> int:
  """Bitwise choice/multiplexer function.

  For each bit position, selects from if_true is mask bit is 1,
  otherwise from if_false.

  Equivalent to: (mask & if_true) | (~mask & if_false)
  Optimized to: if_false ^ (mask & (if_true ^ if_false))

  Args:
      mask: Selection mask
      if_true: Value when mask bit is 1
      if_false: Value when mask bit is 0

  Returns:
      Selected bits
  """
  return if_false ^ (mask & (if_true ^ if_false))


def _majority(x: int, y: int, z: int) -> int:
  """Bitwise majority function.

  For each bit position, returns the majority value of the three inputs.

  Args:
      x: First input value
      y: Second input value
      z: Third input value

  Returns:
      Majority result (32-bit unsigned)
  """
  return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF


def _xor3(x: int, y: int, z: int) -> int:
  """Triple XOR function.

  Args:
      x: First input value
      y: Second input value
      z: Third input value

  Returns:
      x ^ y ^ z (32-bit unsigned)
  """
  return (x ^ y ^ z) & 0xFFFFFFFF


def _nor_mix(x: int, y: int, z: int) -> int:
  """Round 4 nonlinear function: y ^ (x | ~z).

  Args:
      x: First input value
      y: Second input value
      z: Third input value

  Returns:
      Result of y ^ (x | ~z) (32-bit unsigned)
  """
  return (y ^ (x | (0xFFFFFFFF ^ z))) & 0xFFFFFFFF


def _gg_func(b: int, c: int, d: int) -> int:
  """Round 2 nonlinear function: (b & d) | (c & ~d)."""
  return ((b & d) | (c & (0xFFFFFFFF ^ d))) & 0xFFFFFFFF


def _apply_round(
  state: _MD5State,
  words: tuple[int, ...],
  round_idx: int,
  func: Callable[[int, int, int], int],
) -> None:
  """Apply one round of MD5 transformation.

  Args:
      state: Current MD5 state (modified in place)
      words: Message words (16 x 32-bit values)
      round_idx: Round index (0-63)
      func: Nonlinear function to use
  """
  idx = _INDICES[round_idx]
  shift = _SHIFTS[round_idx]
  k_val = _K[round_idx]

  temp = (state.a + func(state.b, state.c, state.d)) & 0xFFFFFFFF
  temp = (temp + words[idx]) & 0xFFFFFFFF
  temp = (temp + k_val) & 0xFFFFFFFF
  temp = _left_rotate(temp, shift)
  temp = (temp + state.b) & 0xFFFFFFFF

  state.a, state.b, state.c, state.d = state.d, temp, state.b, state.c


def _process_chunk(state: _MD5State, chunk: bytes) -> None:
  """Process a single 64-byte chunk.

  Args:
      state: Current MD5 state (modified in place)
      chunk: 64-byte data chunk
  """
  words = struct.unpack("<16I", chunk)
  initial = state.copy()

  funcs = (_choice, _gg_func, _xor3, _nor_mix)
  for i in range(64):
    func_idx = (i >= _ROUND1_END) + (i >= _ROUND2_END) + (i >= _ROUND3_END)
    _apply_round(state, words, i, funcs[func_idx])

  state.add(initial)


def pad_message(message: bytes) -> bytes:
  """Pad message to multiple of 64 bytes.

  MD5 padding: append 0x80, then 0x00 bytes until length ≡ 56 (mod 64),
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


def md5(data: bytes | str) -> str:
  """Compute MD5 hash of input data.

  Args:
      data: Input data (bytes or string)

  Returns:
      32-character hexadecimal hash string

  Example:
      >>> md5(b"hello")
      '5d41402abc4b2a76b9719d911017c592'
      >>> md5("hello")
      '5d41402abc4b2a76b9719d911017c592'
  """
  message = data if isinstance(data, bytes) else data.encode()

  state = _MD5State(
    a=_INITIAL_A,
    b=_INITIAL_B,
    c=_INITIAL_C,
    d=_INITIAL_D,
  )

  padded = pad_message(message)

  for i in range(0, len(padded), 64):
    _process_chunk(state, padded[i : i + 64])

  return state.to_bytes().hex()


# Backward compatibility aliases
left_rotate = _left_rotate
bitwise_choice = _choice
bitwise_majority = _majority
bitwise_xor3 = _xor3
bitwise_nor_mix = _nor_mix


# Round functions for testing (kept for backward compatibility)
def FF(a: int, b: int, c: int, d: int, x: int, s: int, ac: int) -> int:  # noqa: N802, PLR0913
  """Round 1 MD5 transformation function."""
  result = (a + _choice(b, c, d) + x + ac) & 0xFFFFFFFF
  return (_left_rotate(result, s) + b) & 0xFFFFFFFF


def GG(a: int, b: int, c: int, d: int, x: int, s: int, ac: int) -> int:  # noqa: N802, PLR0913
  """Round 2 MD5 transformation function."""
  g = ((b & d) | (c & (0xFFFFFFFF ^ d))) & 0xFFFFFFFF
  result = (a + g + x + ac) & 0xFFFFFFFF
  return (_left_rotate(result, s) + b) & 0xFFFFFFFF


def HH(a: int, b: int, c: int, d: int, x: int, s: int, ac: int) -> int:  # noqa: N802, PLR0913
  """Round 3 MD5 transformation function."""
  result = (a + _xor3(b, c, d) + x + ac) & 0xFFFFFFFF
  return (_left_rotate(result, s) + b) & 0xFFFFFFFF


def II(a: int, b: int, c: int, d: int, x: int, s: int, ac: int) -> int:  # noqa: N802, PLR0913
  """Round 4 MD5 transformation function."""
  result = (a + _nor_mix(b, c, d) + x + ac) & 0xFFFFFFFF
  return (_left_rotate(result, s) + b) & 0xFFFFFFFF
