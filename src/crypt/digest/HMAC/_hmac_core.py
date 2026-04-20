"""Shared HMAC computation core.

Reference: RFC 2104
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from collections.abc import Callable

# Inner and outer pad values (shared across all HMAC variants)
_IPAD: int = 0x36
_OPAD: int = 0x5C


def _compute_hmac(
  key: bytes,
  data: bytes,
  hash_func: Callable[[bytes], str],
  block_size: int,
  _hash_len: int,
) -> bytes:
  """Compute HMAC using the specified hash function.

  Args:
      key: Secret key (any length)
      data: Message data to authenticate
      hash_func: Hash function that returns hex string
      block_size: Block size of the hash function in bytes
      _hash_len: Length of the hash output in bytes

  Returns:
      HMAC result as bytes
  """
  # Step 1: If key is longer than block_size, hash it
  if len(key) > block_size:
    key = bytes.fromhex(hash_func(key))

  # Step 2: If key is shorter than block_size, pad with zeros
  if len(key) < block_size:
    key = key + b"\x00" * (block_size - len(key))

  # Step 3: Create inner and outer padded keys
  inner_key = bytes(b ^ _IPAD for b in key)
  outer_key = bytes(b ^ _OPAD for b in key)

  # Step 4: Compute inner hash: hash(inner_key || data)
  inner_hash = bytes.fromhex(hash_func(inner_key + data))

  # Step 5: Compute outer hash: hash(outer_key || inner_hash)
  return bytes.fromhex(hash_func(outer_key + inner_hash))
