"""Pure Python implementation of HMAC-SHA1.

HMAC (Keyed-Hash Message Authentication Code) is a specific construction
for creating a message authentication code using a cryptographic hash function.

Reference: RFC 2104
"""

from __future__ import annotations

from crypt.digest.HMAC._hmac_core import _compute_hmac
from crypt.digest.SHA.sha1 import sha1
from typing import Final

# Block size for SHA1 is 64 bytes
_BLOCK_SIZE: Final = 64


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
