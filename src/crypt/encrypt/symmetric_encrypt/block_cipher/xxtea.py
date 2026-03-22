"""XXTEA (Corrected Block TEA) block cipher — pure Python implementation.

Operates on variable-length data; treats it as an array of 32-bit words.
Minimum data size: 8 bytes (2 words).
Key size: 128 bits (16 bytes).
"""

import struct

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF
KEY_SIZE = 16


def _mx(z: int, y: int, s: int, key_val: int) -> int:
  return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((s ^ y) + (key_val ^ z))) & MASK


def _parse_key(key: bytes) -> list:
  if len(key) != KEY_SIZE:
    msg = f"Key must be {KEY_SIZE} bytes"
    raise ValueError(msg)
  return list(struct.unpack("<4I", key))


def _pkcs7_pad(data: bytes, block: int = 4) -> bytes:
  # Pad to multiple of 4 bytes (word boundary), minimum 8 bytes
  target = max(8, ((len(data) + block - 1) // block) * block)
  pad = target - len(data)
  if pad == 0:
    target += block
    pad = block
  return data + bytes([pad] * pad)


def _pkcs7_unpad(data: bytes) -> bytes:
  pad = data[-1]
  return data[:-pad]


def encrypt(data: bytes, key: bytes) -> bytes:
  """Encrypt variable-length data (minimum 8 bytes after padding)."""
  padded = _pkcs7_pad(data)
  k = _parse_key(key)
  n = len(padded) // 4
  v = list(struct.unpack(f"<{n}I", padded))

  q = 6 + 52 // n
  s = 0
  z = v[n - 1]
  for _ in range(q):
    s = (s + DELTA) & MASK
    e = (s >> 2) & 3
    for p in range(n - 1):
      y = v[p + 1]
      v[p] = (v[p] + _mx(z, y, s, k[(p & 3) ^ e])) & MASK
      z = v[p]
    y = v[0]
    v[n - 1] = (v[n - 1] + _mx(z, y, s, k[(n - 1 & 3) ^ e])) & MASK
    z = v[n - 1]

  return struct.pack(f"<{n}I", *v)


def decrypt(data: bytes, key: bytes) -> bytes:
  """Decrypt variable-length ciphertext."""
  if len(data) < 8 or len(data) % 4 != 0:
    msg = "Ciphertext must be >= 8 bytes and a multiple of 4 bytes"
    raise ValueError(msg)
  k = _parse_key(key)
  n = len(data) // 4
  v = list(struct.unpack(f"<{n}I", data))

  q = 6 + 52 // n
  s = (DELTA * q) & MASK
  y = v[0]
  for _ in range(q):
    e = (s >> 2) & 3
    for p in range(n - 1, 0, -1):
      z = v[p - 1]
      v[p] = (v[p] - _mx(z, y, s, k[(p & 3) ^ e])) & MASK
      y = v[p]
    z = v[n - 1]
    v[0] = (v[0] - _mx(z, y, s, k[(0 & 3) ^ e])) & MASK
    y = v[0]
    s = (s - DELTA) & MASK

  return _pkcs7_unpad(struct.pack(f"<{n}I", *v))
