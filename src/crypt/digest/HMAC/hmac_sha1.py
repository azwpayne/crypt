"""Pure Python implementation of HMAC-SHA1.

HMAC (Keyed-Hash Message Authentication Code) is a specific construction
for creating a message authentication code using a cryptographic hash function.

Reference: RFC 2104
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
  from collections.abc import Callable

# Import SHA1 implementation
from crypt.digest.SHA.sha1 import sha1

# Block size for SHA1 is 64 bytes
_BLOCK_SIZE: Final = 64

# Inner and outer pad values
_IPAD: Final = 0x36
_OPAD: Final = 0x5C


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
  return bytes.fromhex(hash_func(outer_key + inner_hash))


def hmac_sha1(key: bytes, data: bytes) -> bytes:
  """Compute HMAC-SHA1 of data using the provided key.

  Args:
      key: Secret key (any length)
      data: Message data to authenticate

  Returns:
      20-byte HMAC-SHA1 result

  Example:
      >>> hmac_sha1(b"key", b"data").hex()
      '4f4ca3d5d68ba7cc0dbabdd9df0c2c9e3c2f4d9d'
  """
  return _compute_hmac(key, data, sha1, _BLOCK_SIZE, 20)


def hmac_sha1_hex(key: bytes, data: bytes) -> str:
  """Compute HMAC-SHA1 and return as hex string.

  Args:
      key: Secret key (any length)
      data: Message data to authenticate

  Returns:
      40-character hexadecimal HMAC-SHA1 result

  Example:
      >>> hmac_sha1_hex(b"key", b"data")
      '4f4ca3d5d68ba7cc0dbabdd9df0c2c9e3c2f4d9d'
  """
  return hmac_sha1(key, data).hex()
