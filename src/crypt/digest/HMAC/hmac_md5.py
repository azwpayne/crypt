"""Pure Python implementation of HMAC-MD5.

HMAC (Keyed-Hash Message Authentication Code) is a specific construction
for creating a message authentication code using a cryptographic hash function.

Reference: RFC 2104
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
  from collections.abc import Callable

# Import MD5 implementation
from crypt.digest.MD.md5 import md5

# Block size for MD5 is 64 bytes
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


def hmac_md5(key: bytes, data: bytes) -> bytes:
  """Compute HMAC-MD5 of data using the provided key.

  Args:
      key: Secret key (any length)
      data: Message data to authenticate

  Returns:
      16-byte HMAC-MD5 result

  Example:
      >>> hmac_md5(b"key", b"data").hex()
      '1f3870be274f6c49b3e31a0c6728957f'
  """
  return _compute_hmac(key, data, md5, _BLOCK_SIZE, 16)


def hmac_md5_hex(key: bytes, data: bytes) -> str:
  """Compute HMAC-MD5 and return as hex string.

  Args:
      key: Secret key (any length)
      data: Message data to authenticate

  Returns:
      32-character hexadecimal HMAC-MD5 result

  Example:
      >>> hmac_md5_hex(b"key", b"data")
      '1f3870be274f6c49b3e31a0c6728957f'
  """
  return hmac_md5(key, data).hex()
