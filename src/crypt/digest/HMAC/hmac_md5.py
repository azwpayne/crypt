"""Pure Python implementation of HMAC-MD5.

HMAC (Keyed-Hash Message Authentication Code) is a specific construction
for creating a message authentication code using a cryptographic hash function.

Reference: RFC 2104
"""

from __future__ import annotations

from crypt.digest.HMAC._hmac_core import _compute_hmac
from crypt.digest.MD.md5 import md5
from typing import Final

# Block size for MD5 is 64 bytes
_BLOCK_SIZE: Final = 64


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
