"""BLAKE3 hash algorithm implementation.

This module provides BLAKE3 hashing functionality. It uses the reference
'blake3' library for the core implementation to ensure correctness.

For a pure Python implementation, the BLAKE3 algorithm is significantly more
complex than BLAKE2 due to its Merkle tree structure and parallelization.
The core compression function is similar to BLAKE2s (7 rounds instead of 10),
but the tree-based input processing and XOF (extendable output) mode require
careful implementation.

Reference: https://github.com/BLAKE3-team/BLAKE3
"""

from __future__ import annotations

try:
  import blake3 as _blake3

  _HAS_BLAKE3 = True
except ImportError:
  _HAS_BLAKE3 = False
  _blake3 = None  # type: ignore[misc,assignment]


# Error messages
_BLAKE3_NOT_INSTALLED_MSG = (
  "The 'blake3' library is required. Install it with: uv add blake3"
)


def blake3(
  data: bytes, *, key: bytes | None = None, derive_key_context: bytes | None = None
) -> str:
  """Compute the BLAKE3 hash of input data.

  Args:
      data: Input data to hash
      key: Optional key for keyed hashing (must be 32 bytes)
      derive_key_context: Optional context for key derivation mode

  Returns:
      Hexadecimal hash string (64 characters = 256 bits)

  Raises:
      ValueError: If key is not exactly 32 bytes
      ValueError: If derive_key_context is provided with key
      RuntimeError: If blake3 library is not installed

  Example:
      >>> blake3(b"hello")
      'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f'
  """
  if not _HAS_BLAKE3 or _blake3 is None:
    raise RuntimeError(_BLAKE3_NOT_INSTALLED_MSG)

  if key is not None and derive_key_context is not None:
    msg = "Cannot use both key and derive_key_context"
    raise ValueError(msg)

  if key is not None:
    if len(key) != 32:
      msg = "key must be exactly 32 bytes"
      raise ValueError(msg)
    hasher = _blake3.blake3(key=key)
  elif derive_key_context is not None:
    hasher = _blake3.blake3(derive_key_context=derive_key_context.decode())
  else:
    hasher = _blake3.blake3()

  hasher.update(data)
  return hasher.hexdigest()


def blake3_xof(data: bytes, length: int, *, key: bytes | None = None) -> bytes:
  """Compute extendable BLAKE3 output (XOF mode).

  Args:
      data: Input data to hash
      length: Number of output bytes desired (can be any size)
      key: Optional key for keyed hashing (must be 32 bytes)

  Returns:
      Raw bytes of specified length

  Raises:
      ValueError: If length is negative
      ValueError: If key is not exactly 32 bytes
      RuntimeError: If blake3 library is not installed

  Example:
      >>> blake3_xof(b"hello", 100)  # Get 100 bytes of output
      b'...'
  """
  if not _HAS_BLAKE3 or _blake3 is None:
    raise RuntimeError(_BLAKE3_NOT_INSTALLED_MSG)

  if length < 0:
    msg = "length must be non-negative"
    raise ValueError(msg)

  if key is not None and len(key) != 32:
    msg = "key must be exactly 32 bytes"
    raise ValueError(msg)

  if length == 0:
    return b""

  hasher = _blake3.blake3(key=key) if key is not None else _blake3.blake3()

  hasher.update(data)
  return hasher.digest(length=length)


def blake3_keyed(data: bytes, key: bytes) -> str:
  """Compute keyed BLAKE3 hash.

  This is a convenience function for keyed hashing.

  Args:
      data: Input data to hash
      key: Key for keyed hashing (must be 32 bytes)

  Returns:
      Hexadecimal hash string (64 characters = 256 bits)

  Raises:
      ValueError: If key is not exactly 32 bytes
      RuntimeError: If blake3 library is not installed

  Example:
      >>> blake3_keyed(b"hello", b"a" * 32)
      '...'
  """
  return blake3(data, key=key)
