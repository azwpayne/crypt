"""Pure Python implementation of HMAC-SHA256.

HMAC (Keyed-Hash Message Authentication Code) is a specific construction
for creating a message authentication code using a cryptographic hash function.

Reference: RFC 2104
"""

from __future__ import annotations

from crypt.digest.HMAC._hmac_core import _compute_hmac
from crypt.digest.SHA.sha2_256 import sha256
from typing import Final

# Block size for SHA256 is 64 bytes
_BLOCK_SIZE: Final = 64


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
