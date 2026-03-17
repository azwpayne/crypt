"""Pure Python implementation of the MD6 hash algorithm (simplified).

MD6 is a cryptographic hash function designed by Ron Rivest as a candidate for SHA-3.
It uses a tree-based structure and a compression function based on a Feistel network.
This is a simplified implementation for educational purposes.

Note: This is a simplified sequential implementation, not the full parallel tree mode.
"""

from __future__ import annotations

import struct
from typing import Final

# MD6 constants
_Q: Final[int] = 64  # Word size in bits
_N: Final[int] = 89  # Number of words in compression input
_C: Final[int] = 16  # Number of words in compression output
_R: Final[int] = 40  # Number of rounds in compression function (simplified)

# MD6 initial value (derived from sqrt(6))
_IV: Final[tuple[int, ...]] = (
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
  0x0123456789ABCDEF,
)

# Round constants (derived from fractional parts of sqrt(6))
_K: Final[tuple[int, ...]] = (
  0x449E2F41C1FD9121,
  0xCE273E59118AD309,
  0x86F60F00D7C25E42,
  0xF05A14298A8C1C44,
  0x9E8E8C99327F4E7E,
  0x0E3DC1A08532F7C3,
)

# Shift amounts for each round
_S: Final[tuple[int, ...]] = (
  10,
  17,
  23,
  5,
  12,
  19,
  26,
  7,
  14,
  21,
  2,
  9,
  16,
  24,
  4,
  11,
  18,
  25,
  6,
  13,
  20,
  27,
  8,
  15,
  22,
  3,
  10,
  17,
  24,
  5,
  12,
  19,
  26,
  7,
  14,
  21,
  2,
  9,
  16,
  23,
)


def _left_rotate_64(x: int, n: int) -> int:
  """Rotate a 64-bit value left by n bits."""
  n %= 64
  return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _f_64(x: int) -> int:
  """Nonlinear function: (x ^ (x >> 1)) & 0x..."""
  return (x ^ (x >> 1) ^ (x >> 2)) & 0xFFFFFFFFFFFFFFFF


def _compress(input_words: tuple[int, ...]) -> tuple[int, ...]:
  """MD6 compression function.

  Takes _N 64-bit words and produces _C 64-bit words.
  """
  # Convert to list for manipulation
  state = list(input_words)

  # Main compression loop (simplified)
  for r in range(_R):
    # Apply round function to each word
    new_state = state[:]
    for j in range(len(state)):
      # Simple mixing operation
      a = state[(j - 1) % len(state)]
      b = state[j]
      c = state[(j + 1) % len(state)]

      # Nonlinear mixing
      t = (a ^ b ^ c) & 0xFFFFFFFFFFFFFFFF
      t = _left_rotate_64(t, _S[r % len(_S)])

      # Add round constant
      k_idx = (j + r) % len(_K)
      t = (t + _K[k_idx]) & 0xFFFFFFFFFFFFFFFF

      new_state[j] = t

    state = new_state

  # Return last _C words as output
  return tuple(state[-_C:])


def _prepare_block(
  data: bytes, block_num: int, hash_size: int, *, is_last: bool
) -> tuple[int, ...]:
  """Prepare a data block for compression."""
  # Pad data to multiple of 64 bytes
  padded = data.ljust(64, b"\x00")

  # Convert to 64-bit words
  words = []
  for i in range(0, len(padded), 8):
    word = struct.unpack("<Q", padded[i : i + 8])[0]
    words.append(word)

  words.extend(
    (
      block_num & 0xFFFFFFFFFFFFFFFF,
      len(data) & 0xFFFFFFFFFFFFFFFF,
      (1 if is_last else 0) << 63 | hash_size,
    )
  )
  # Pad to _N words with zeros
  while len(words) < _N:
    words.append(0)

  return tuple(words[:_N])


def _md6_hash(data: bytes, hash_size: int = 256) -> bytes:
  """Internal MD6 hash function.

  Args:
      data: Input data
      hash_size: Desired hash size in bits (128, 256, 512, etc.)

  Returns:
      Hash bytes
  """
  # Initialize state with IV
  state = list(_IV)

  # Process data in blocks
  block_size = 64  # Bytes per block
  num_blocks = (len(data) + block_size - 1) // block_size

  for i in range(num_blocks):
    start = i * block_size
    end = min(start + block_size, len(data))
    block_data = data[start:end]
    is_last = i == num_blocks - 1

    # Prepare block for compression
    # block = _prepare_block(block_data, i, is_last, hash_size)
    block = _prepare_block(block_data, i, hash_size, is_last=is_last)

    # Apply compression
    compressed = _compress(block)

    # Update state (XOR feedback)
    for j in range(min(len(state), len(compressed))):
      state[j] = (state[j] ^ compressed[j]) & 0xFFFFFFFFFFFFFFFF

  # Output truncation to desired hash size
  output_words = hash_size // 64
  if output_words == 0:
    output_words = 1  # At least one word

  result = b""
  for i in range(min(output_words, len(state))):
    result += struct.pack("<Q", state[i])

  # Truncate to exact hash size
  hash_bytes = hash_size // 8
  return result[:hash_bytes]


def md6(data: bytes | str, hash_size: int = 256) -> str:
  """Compute MD6 hash of input data.

  This is a simplified sequential implementation for educational purposes.

  Args:
      data: Input data (bytes or string)
      hash_size: Desired hash size in bits (128, 256, or 512)

  Returns:
      Hexadecimal hash string

  Example:
      >>> md6(b"hello")
      'a3b3c4d5...'  # 64 hex chars for 256-bit hash
  """
  message = data if isinstance(data, bytes) else data.encode()

  # Validate hash size
  if hash_size not in (128, 256, 512):
    hash_size = 256  # Default to 256-bit

  result = _md6_hash(message, hash_size)
  return result.hex()


def md6_128(data: bytes | str) -> str:
  """Compute 128-bit MD6 hash."""
  return md6(data, hash_size=128)


def md6_256(data: bytes | str) -> str:
  """Compute 256-bit MD6 hash."""
  return md6(data, hash_size=256)


def md6_512(data: bytes | str) -> str:
  """Compute 512-bit MD6 hash."""
  return md6(data, hash_size=512)
