"""XTEA (eXtended TEA) block cipher — pure Python implementation.

Block size : 64 bits (8 bytes)
Key size   : 128 bits (16 bytes)
Rounds     : 64 (default)
"""

import struct

BLOCK_SIZE = 8
KEY_SIZE = 16
DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def _xtea_encipher(v0: int, v1: int, key: tuple, rounds: int = 64) -> tuple:
  s = 0
  for _ in range(rounds):
    v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (s + key[s & 3]))) & MASK
    s = (s + DELTA) & MASK
    v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (s + key[(s >> 11) & 3]))) & MASK
  return v0, v1


def _xtea_decipher(v0: int, v1: int, key: tuple, rounds: int = 64) -> tuple:
  s = (DELTA * rounds) & MASK
  for _ in range(rounds):
    v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (s + key[(s >> 11) & 3]))) & MASK
    s = (s - DELTA) & MASK
    v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (s + key[s & 3]))) & MASK
  return v0, v1


def _parse_key(key: bytes) -> tuple:
  if len(key) != KEY_SIZE:
    msg = f"Key must be {KEY_SIZE} bytes"
    raise ValueError(msg)
  return struct.unpack(">4I", key)


def _pkcs7_pad(data: bytes, block: int = BLOCK_SIZE) -> bytes:
  pad = block - len(data) % block
  return data + bytes([pad] * pad)


def _pkcs7_unpad(data: bytes) -> bytes:
  pad = data[-1]
  return data[:-pad]


def encrypt_block(block: bytes, key: bytes) -> bytes:
  """Encrypt a single 8-byte block."""
  if len(block) != BLOCK_SIZE:
    msg = f"Block must be {BLOCK_SIZE} bytes"
    raise ValueError(msg)
  v0, v1 = struct.unpack(">2I", block)
  v0, v1 = _xtea_encipher(v0, v1, _parse_key(key))
  return struct.pack(">2I", v0, v1)


def decrypt_block(block: bytes, key: bytes) -> bytes:
  """Decrypt a single 8-byte block."""
  if len(block) != BLOCK_SIZE:
    msg = f"Block must be {BLOCK_SIZE} bytes"
    raise ValueError(msg)
  v0, v1 = struct.unpack(">2I", block)
  v0, v1 = _xtea_decipher(v0, v1, _parse_key(key))
  return struct.pack(">2I", v0, v1)


def xtea_ecb_encrypt(data: bytes, key: bytes) -> bytes:
  """ECB mode encryption with PKCS#7 padding."""
  padded = _pkcs7_pad(data)
  return b"".join(
    encrypt_block(padded[i : i + BLOCK_SIZE], key)
    for i in range(0, len(padded), BLOCK_SIZE)
  )


def xtea_ecb_decrypt(data: bytes, key: bytes) -> bytes:
  """ECB mode decryption, removes PKCS#7 padding."""
  if len(data) % BLOCK_SIZE != 0:
    msg = "Ciphertext length must be a multiple of block size"
    raise ValueError(msg)
  raw = b"".join(
    decrypt_block(data[i : i + BLOCK_SIZE], key)
    for i in range(0, len(data), BLOCK_SIZE)
  )
  return _pkcs7_unpad(raw)


def xtea_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
  """CBC mode encryption."""
  if len(iv) != BLOCK_SIZE:
    msg = f"IV must be {BLOCK_SIZE} bytes"
    raise ValueError(msg)
  padded = _pkcs7_pad(data)
  result = b""
  prev = iv
  for i in range(0, len(padded), BLOCK_SIZE):
    block = bytes(a ^ b for a, b in zip(padded[i : i + BLOCK_SIZE], prev, strict=False))
    enc = encrypt_block(block, key)
    result += enc
    prev = enc
  return result


def xtea_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
  """CBC mode decryption."""
  if len(iv) != BLOCK_SIZE:
    msg = f"IV must be {BLOCK_SIZE} bytes"
    raise ValueError(msg)
  if len(data) % BLOCK_SIZE != 0:
    msg = "Ciphertext length must be a multiple of block size"
    raise ValueError(msg)
  result = b""
  prev = iv
  for i in range(0, len(data), BLOCK_SIZE):
    block = data[i : i + BLOCK_SIZE]
    dec = decrypt_block(block, key)
    result += bytes(a ^ b for a, b in zip(dec, prev, strict=False))
    prev = block
  return _pkcs7_unpad(result)
