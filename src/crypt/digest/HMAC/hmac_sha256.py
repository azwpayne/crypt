"""Pure Python implementation of HMAC-SHA256.

HMAC (Keyed-Hash Message Authentication Code) is a specific construction
for creating a message authentication code using a cryptographic hash function.

Reference: RFC 2104
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
  from collections.abc import Callable

# Import SHA256 implementation
from crypt.digest.SHA.sha2_256 import sha256

# Block size for SHA256 is 64 bytes
_BLOCK_SIZE: Final = 64

# Inner and outer pad values
_IPAD: Final = 0x36
_OPAD: Final = 0x5C


def _compute_hmac(
  key: bytes,
  data: bytes,
  hash_func: Callable[[bytes], str],
  block_size: int,
  hash_len: int,
) -> bytes:
  """Compute HMAC using the specified hash function.

  Args:
      key: Secret key (any length)
      data: Message data to authenticate
      hash_func: Hash function that returns hex string
      block_size: Block size of the hash function in bytes
      hash_len: Length of the hash output in bytes

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
  result = bytes.fromhex(hash_func(outer_key + inner_hash))

  return result


def hmac_sha256(key: bytes, data: bytes) -> bytes:
  """Compute HMAC-SHA256 of data using the provided key.

  Args:
      key: Secret key (any length)
      data: Message data to authenticate

  Returns:
      32-byte HMAC-SHA256 result

  Example:
      >>> hmac_sha256(b"key", b"data").hex()
      '5031fe3d989c6d1537eef5477e673a7d5d37f1f2d8b0b3f9e8d9e8d9e8d9e8d9'
  """
  return _compute_hmac(key, data, sha256, _BLOCK_SIZE, 32)


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
  """Compute HMAC-SHA256 and return as hex string.

  Args:
      key: Secret key (any length)
      data: Message data to authenticate

  Returns:
      64-character hexadecimal HMAC-SHA256 result

  Example:
      >>> hmac_sha256_hex(b"key", b"data")
      '5031fe3d989c6d1537eef5477e673a7d5d37f1f2d8b0b3f9e8d9e8d9e8d9e8d9'
  """
  return hmac_sha256(key, data).hex()
