"""Pure Python implementation of AES-CMAC (RFC 4493).

AES-CMAC is a block cipher-based message authentication code (MAC) algorithm
using AES. It is based on the CBC-MAC construction with additional processing
to handle messages of any length securely.

Reference: RFC 4493 — The AES-CMAC Algorithm
"""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
  _encrypt_block,
  _get_key_params,
  key_expansion,
)
from typing import Final

_BLOCK_SIZE: Final = 16
_Rb_128: Final = 0x87  # Rb constant for AES (128-bit block)


def _generate_subkeys(key: bytes) -> tuple[bytes, bytes]:
  """Generate CMAC subkeys K1 and K2 per RFC 4493 Section 2.3.

  Steps:
    1. L = AES_Encrypt(zero_block, key)
    2. K1 = L << 1  (if MSB set, XOR Rb after shift)
    3. K2 = K1 << 1 (same)

  Args:
      key: AES key (16, 24, or 32 bytes).

  Returns:
      Tuple of (K1, K2), each 16 bytes.
  """
  _nk, nr = _get_key_params(key)
  expanded_key = key_expansion(key)

  # Step 1: L = AES_Encrypt(16 zero bytes, key)
  zero_block = b"\x00" * _BLOCK_SIZE
  subkey_l = _encrypt_block(zero_block, expanded_key, nr)

  # Step 2: K1 = L << 1
  k1 = _left_shift_block(subkey_l)

  # Step 3: K2 = K1 << 1
  k2 = _left_shift_block(k1)

  return k1, k2


def _left_shift_block(block: bytes) -> bytes:
  """Left-shift a 16-byte block by 1 bit, with conditional XOR of Rb.

  If the MSB of the block is set, XOR the last byte with Rb (0x87 for AES).

  Args:
      block: 16-byte block to shift.

  Returns:
      The shifted 16-byte block.
  """
  result = bytearray(_BLOCK_SIZE)
  carry = 0

  for i in range(_BLOCK_SIZE - 1, -1, -1):
    b = block[i]
    result[i] = ((b << 1) | carry) & 0xFF
    carry = (b >> 7) & 1

  # If MSB was set, XOR last byte with Rb
  if carry:
    result[_BLOCK_SIZE - 1] ^= _Rb_128

  return bytes(result)


def cmac(key: bytes, message: bytes) -> bytes:
  """Compute AES-CMAC of a message per RFC 4493.

  Supports AES-128, AES-192, and AES-256 based on key length.

  Args:
      key: AES key (16, 24, or 32 bytes).
      message: Message to authenticate (any length, including empty).

  Returns:
      16-byte CMAC tag.

  Raises:
      ValueError: If key length is not 16, 24, or 32 bytes.

  Example:
      >>> key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
      >>> cmac(key, b"").hex()
      'bb1d6929e95937287fa37d129b756746'
  """
  _nk, nr = _get_key_params(key)
  expanded_key = key_expansion(key)
  k1, k2 = _generate_subkeys(key)

  # Split message into 16-byte blocks
  n = len(message) // _BLOCK_SIZE
  remainder = len(message) % _BLOCK_SIZE

  if n == 0 and remainder == 0:
    # Empty message: pad with 0x80 || zeros, XOR with K2
    padded = b"\x80" + b"\x00" * (_BLOCK_SIZE - 1)
    last_block = bytes(a ^ b for a, b in zip(padded, k2, strict=False))
    blocks: list[bytes] = [last_block]
  elif remainder == 0 and n > 0:
    # Message is a positive multiple of block size:
    # last block XORed with K1 (no padding)
    blocks = [message[i * _BLOCK_SIZE : (i + 1) * _BLOCK_SIZE] for i in range(n)]
    last_block = bytes(a ^ b for a, b in zip(blocks[-1], k1, strict=False))
    blocks[-1] = last_block
  else:
    # Message is not a multiple of block size:
    # pad last block with 0x80 || zeros, XOR with K2
    blocks = [message[i * _BLOCK_SIZE : (i + 1) * _BLOCK_SIZE] for i in range(n)]
    last_partial = message[n * _BLOCK_SIZE :]
    padded = last_partial + b"\x80" + b"\x00" * (_BLOCK_SIZE - len(last_partial) - 1)
    last_block = bytes(a ^ b for a, b in zip(padded, k2, strict=False))
    blocks.append(last_block)

  # CBC-MAC
  mac = b"\x00" * _BLOCK_SIZE
  for block in blocks:
    xored = bytes(a ^ b for a, b in zip(mac, block, strict=False))
    mac = _encrypt_block(xored, expanded_key, nr)

  return mac


def cmac_verify(key: bytes, message: bytes, tag: bytes) -> bool:
  """Verify an AES-CMAC tag in constant time.

  Args:
      key: AES key (16, 24, or 32 bytes).
      message: Message to verify.
      tag: Expected 16-byte CMAC tag.

  Returns:
      True if the tag is valid, False otherwise.
  """
  expected = cmac(key, message)
  return _constant_time_compare(expected, tag)


def _constant_time_compare(a: bytes, b: bytes) -> bool:
  """Compare two byte strings in constant time.

  Prevents timing side-channel attacks by always comparing all bytes
  regardless of where a mismatch occurs.

  Args:
      a: First byte string.
      b: Second byte string.

  Returns:
      True if equal, False otherwise.
  """
  if len(a) != len(b):
    return False
  result = 0
  for x, y in zip(a, b, strict=False):
    result |= x ^ y
  return result == 0
