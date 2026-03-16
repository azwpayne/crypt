# @time    : 2026/1/6 15:54
# @name    : AES.py
# @author  : azwpayne
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : AES (Advanced Encryption Standard) block cipher implementation.
#           Supports AES-128, AES-192, AES-256 with ECB, CBC, and CTR modes.

from typing import Literal

# AES S-box for SubBytes transformation
S_BOX = [
  0x63,
  0x7C,
  0x77,
  0x7B,
  0xF2,
  0x6B,
  0x6F,
  0xC5,
  0x30,
  0x01,
  0x67,
  0x2B,
  0xFE,
  0xD7,
  0xAB,
  0x76,
  0xCA,
  0x82,
  0xC9,
  0x7D,
  0xFA,
  0x59,
  0x47,
  0xF0,
  0xAD,
  0xD4,
  0xA2,
  0xAF,
  0x9C,
  0xA4,
  0x72,
  0xC0,
  0xB7,
  0xFD,
  0x93,
  0x26,
  0x36,
  0x3F,
  0xF7,
  0xCC,
  0x34,
  0xA5,
  0xE5,
  0xF1,
  0x71,
  0xD8,
  0x31,
  0x15,
  0x04,
  0xC7,
  0x23,
  0xC3,
  0x18,
  0x96,
  0x05,
  0x9A,
  0x07,
  0x12,
  0x80,
  0xE2,
  0xEB,
  0x27,
  0xB2,
  0x75,
  0x09,
  0x83,
  0x2C,
  0x1A,
  0x1B,
  0x6E,
  0x5A,
  0xA0,
  0x52,
  0x3B,
  0xD6,
  0xB3,
  0x29,
  0xE3,
  0x2F,
  0x84,
  0x53,
  0xD1,
  0x00,
  0xED,
  0x20,
  0xFC,
  0xB1,
  0x5B,
  0x6A,
  0xCB,
  0xBE,
  0x39,
  0x4A,
  0x4C,
  0x58,
  0xCF,
  0xD0,
  0xEF,
  0xAA,
  0xFB,
  0x43,
  0x4D,
  0x33,
  0x85,
  0x45,
  0xF9,
  0x02,
  0x7F,
  0x50,
  0x3C,
  0x9F,
  0xA8,
  0x51,
  0xA3,
  0x40,
  0x8F,
  0x92,
  0x9D,
  0x38,
  0xF5,
  0xBC,
  0xB6,
  0xDA,
  0x21,
  0x10,
  0xFF,
  0xF3,
  0xD2,
  0xCD,
  0x0C,
  0x13,
  0xEC,
  0x5F,
  0x97,
  0x44,
  0x17,
  0xC4,
  0xA7,
  0x7E,
  0x3D,
  0x64,
  0x5D,
  0x19,
  0x73,
  0x60,
  0x81,
  0x4F,
  0xDC,
  0x22,
  0x2A,
  0x90,
  0x88,
  0x46,
  0xEE,
  0xB8,
  0x14,
  0xDE,
  0x5E,
  0x0B,
  0xDB,
  0xE0,
  0x32,
  0x3A,
  0x0A,
  0x49,
  0x06,
  0x24,
  0x5C,
  0xC2,
  0xD3,
  0xAC,
  0x62,
  0x91,
  0x95,
  0xE4,
  0x79,
  0xE7,
  0xC8,
  0x37,
  0x6D,
  0x8D,
  0xD5,
  0x4E,
  0xA9,
  0x6C,
  0x56,
  0xF4,
  0xEA,
  0x65,
  0x7A,
  0xAE,
  0x08,
  0xBA,
  0x78,
  0x25,
  0x2E,
  0x1C,
  0xA6,
  0xB4,
  0xC6,
  0xE8,
  0xDD,
  0x74,
  0x1F,
  0x4B,
  0xBD,
  0x8B,
  0x8A,
  0x70,
  0x3E,
  0xB5,
  0x66,
  0x48,
  0x03,
  0xF6,
  0x0E,
  0x61,
  0x35,
  0x57,
  0xB9,
  0x86,
  0xC1,
  0x1D,
  0x9E,
  0xE1,
  0xF8,
  0x98,
  0x11,
  0x69,
  0xD9,
  0x8E,
  0x94,
  0x9B,
  0x1E,
  0x87,
  0xE9,
  0xCE,
  0x55,
  0x28,
  0xDF,
  0x8C,
  0xA1,
  0x89,
  0x0D,
  0xBF,
  0xE6,
  0x42,
  0x68,
  0x41,
  0x99,
  0x2D,
  0x0F,
  0xB0,
  0x54,
  0xBB,
  0x16,
]

# Inverse S-box for InvSubBytes transformation
INV_S_BOX = [
  0x52,
  0x09,
  0x6A,
  0xD5,
  0x30,
  0x36,
  0xA5,
  0x38,
  0xBF,
  0x40,
  0xA3,
  0x9E,
  0x81,
  0xF3,
  0xD7,
  0xFB,
  0x7C,
  0xE3,
  0x39,
  0x82,
  0x9B,
  0x2F,
  0xFF,
  0x87,
  0x34,
  0x8E,
  0x43,
  0x44,
  0xC4,
  0xDE,
  0xE9,
  0xCB,
  0x54,
  0x7B,
  0x94,
  0x32,
  0xA6,
  0xC2,
  0x23,
  0x3D,
  0xEE,
  0x4C,
  0x95,
  0x0B,
  0x42,
  0xFA,
  0xC3,
  0x4E,
  0x08,
  0x2E,
  0xA1,
  0x66,
  0x28,
  0xD9,
  0x24,
  0xB2,
  0x76,
  0x5B,
  0xA2,
  0x49,
  0x6D,
  0x8B,
  0xD1,
  0x25,
  0x72,
  0xF8,
  0xF6,
  0x64,
  0x86,
  0x68,
  0x98,
  0x16,
  0xD4,
  0xA4,
  0x5C,
  0xCC,
  0x5D,
  0x65,
  0xB6,
  0x92,
  0x6C,
  0x70,
  0x48,
  0x50,
  0xFD,
  0xED,
  0xB9,
  0xDA,
  0x5E,
  0x15,
  0x46,
  0x57,
  0xA7,
  0x8D,
  0x9D,
  0x84,
  0x90,
  0xD8,
  0xAB,
  0x00,
  0x8C,
  0xBC,
  0xD3,
  0x0A,
  0xF7,
  0xE4,
  0x58,
  0x05,
  0xB8,
  0xB3,
  0x45,
  0x06,
  0xD0,
  0x2C,
  0x1E,
  0x8F,
  0xCA,
  0x3F,
  0x0F,
  0x02,
  0xC1,
  0xAF,
  0xBD,
  0x03,
  0x01,
  0x13,
  0x8A,
  0x6B,
  0x3A,
  0x91,
  0x11,
  0x41,
  0x4F,
  0x67,
  0xDC,
  0xEA,
  0x97,
  0xF2,
  0xCF,
  0xCE,
  0xF0,
  0xB4,
  0xE6,
  0x73,
  0x96,
  0xAC,
  0x74,
  0x22,
  0xE7,
  0xAD,
  0x35,
  0x85,
  0xE2,
  0xF9,
  0x37,
  0xE8,
  0x1C,
  0x75,
  0xDF,
  0x6E,
  0x47,
  0xF1,
  0x1A,
  0x71,
  0x1D,
  0x29,
  0xC5,
  0x89,
  0x6F,
  0xB7,
  0x62,
  0x0E,
  0xAA,
  0x18,
  0xBE,
  0x1B,
  0xFC,
  0x56,
  0x3E,
  0x4B,
  0xC6,
  0xD2,
  0x79,
  0x20,
  0x9A,
  0xDB,
  0xC0,
  0xFE,
  0x78,
  0xCD,
  0x5A,
  0xF4,
  0x1F,
  0xDD,
  0xA8,
  0x33,
  0x88,
  0x07,
  0xC7,
  0x31,
  0xB1,
  0x12,
  0x10,
  0x59,
  0x27,
  0x80,
  0xEC,
  0x5F,
  0x60,
  0x51,
  0x7F,
  0xA9,
  0x19,
  0xB5,
  0x4A,
  0x0D,
  0x2D,
  0xE5,
  0x7A,
  0x9F,
  0x93,
  0xC9,
  0x9C,
  0xEF,
  0xA0,
  0xE0,
  0x3B,
  0x4D,
  0xAE,
  0x2A,
  0xF5,
  0xB0,
  0xC8,
  0xEB,
  0xBB,
  0x3C,
  0x83,
  0x53,
  0x99,
  0x61,
  0x17,
  0x2B,
  0x04,
  0x7E,
  0xBA,
  0x77,
  0xD6,
  0x26,
  0xE1,
  0x69,
  0x14,
  0x63,
  0x55,
  0x21,
  0x0C,
  0x7D,
]

# Round constants for key expansion
RCON = [
  0x01,
  0x02,
  0x04,
  0x08,
  0x10,
  0x20,
  0x40,
  0x80,
  0x1B,
  0x36,
  0x6C,
  0xD8,
  0xAB,
  0x4D,
  0x9A,
]


def sub_bytes(state: bytearray, inv: bool = False) -> None:
  """
  SubBytes transformation - non-linear byte substitution.

  Each byte in the state is replaced with its corresponding value
  from the S-box (or inverse S-box for decryption).

  Args:
      state: The 16-byte state array to transform (modified in place).
      inv: If True, use inverse S-box for decryption.
  """
  sbox = INV_S_BOX if inv else S_BOX
  for i in range(16):
    state[i] = sbox[state[i]]


def shift_rows(state: bytearray, inv: bool = False) -> None:
  """
  ShiftRows transformation - cyclic shift of rows.

  Row 0: no shift
  Row 1: shift left by 1 (right by 1 for decryption)
  Row 2: shift left by 2 (right by 2 for decryption)
  Row 3: shift left by 3 (right by 3 for decryption)

  Args:
      state: The 16-byte state array to transform (modified in place).
      inv: If True, perform inverse shift for decryption.
  """
  # State is column-major: state[i] is row i%4, column i//4
  # Row 0: indices 0, 4, 8, 12
  # Row 1: indices 1, 5, 9, 13
  # Row 2: indices 2, 6, 10, 14
  # Row 3: indices 3, 7, 11, 15

  if inv:
    # Inverse: shift right
    # Row 1: shift right by 1
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    # Row 2: shift right by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift right by 3 (left by 1)
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
  else:
    # Forward: shift left
    # Row 1: shift left by 1
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    # Row 2: shift left by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift left by 3 (right by 1)
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _gf_mul(a: int, b: int) -> int:
  """
  Multiply two bytes in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).

  Args:
      a: First byte.
      b: Second byte.

  Returns:
      The product in GF(2^8).
  """
  result = 0
  for _ in range(8):
    if b & 1:
      result ^= a
    high_bit = a & 0x80
    a = (a << 1) & 0xFF
    if high_bit:
      a ^= 0x1B  # 0x11b without the x^8 term
    b >>= 1
  return result


def mix_columns(state: bytearray, inv: bool = False) -> None:
  """
  MixColumns transformation - column-wise mixing using matrix multiplication.

  Each column is treated as a polynomial and multiplied modulo x^4 + 1
  with a fixed polynomial.

  Args:
      state: The 16-byte state array to transform (modified in place).
      inv: If True, use inverse mixing matrix for decryption.
  """
  for col in range(4):
    i = col * 4
    a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]

    if inv:
      # Inverse MixColumns: multiply by [0x0e, 0x0b, 0x0d, 0x09]
      state[i] = (
        _gf_mul(0x0E, a0) ^ _gf_mul(0x0B, a1) ^ _gf_mul(0x0D, a2) ^ _gf_mul(0x09, a3)
      )
      state[i + 1] = (
        _gf_mul(0x09, a0) ^ _gf_mul(0x0E, a1) ^ _gf_mul(0x0B, a2) ^ _gf_mul(0x0D, a3)
      )
      state[i + 2] = (
        _gf_mul(0x0D, a0) ^ _gf_mul(0x09, a1) ^ _gf_mul(0x0E, a2) ^ _gf_mul(0x0B, a3)
      )
      state[i + 3] = (
        _gf_mul(0x0B, a0) ^ _gf_mul(0x0D, a1) ^ _gf_mul(0x09, a2) ^ _gf_mul(0x0E, a3)
      )
    else:
      # Forward MixColumns: multiply by [0x02, 0x03, 0x01, 0x01]
      state[i] = _gf_mul(0x02, a0) ^ _gf_mul(0x03, a1) ^ a2 ^ a3
      state[i + 1] = a0 ^ _gf_mul(0x02, a1) ^ _gf_mul(0x03, a2) ^ a3
      state[i + 2] = a0 ^ a1 ^ _gf_mul(0x02, a2) ^ _gf_mul(0x03, a3)
      state[i + 3] = _gf_mul(0x03, a0) ^ a1 ^ a2 ^ _gf_mul(0x02, a3)


def add_round_key(state: bytearray, round_key: bytes) -> None:
  """
  AddRoundKey transformation - XOR state with round key.

  Args:
      state: The 16-byte state array (modified in place).
      round_key: The 16-byte round key.
  """
  for i in range(16):
    state[i] ^= round_key[i]


def key_expansion(key: bytes) -> list[int]:
  """
  Expand the cipher key into round keys.

  Args:
      key: The cipher key (16, 24, or 32 bytes for AES-128, AES-192, AES-256).

  Returns:
      List of expanded key bytes.
  """
  key_len = len(key)
  if key_len == 16:
    nk, nr = 4, 10  # AES-128
  elif key_len == 24:
    nk, nr = 6, 12  # AES-192
  elif key_len == 32:
    nk, nr = 8, 14  # AES-256
  else:
    msg = f"Invalid key length: {key_len}. Must be 16, 24, or 32 bytes."
    raise ValueError(msg)

  # Convert key to list of words (4 bytes each)
  w = [key[i : i + 4] for i in range(0, key_len, 4)]

  for i in range(nk, 4 * (nr + 1)):
    temp = w[i - 1]
    if i % nk == 0:
      # RotWord and SubWord
      temp = bytes([S_BOX[b] for b in temp[1:] + temp[:1]])
      # XOR with Rcon
      temp = bytes([temp[j] ^ (RCON[(i // nk) - 1] if j == 0 else 0) for j in range(4)])
    elif nk > 6 and i % nk == 4:
      # Additional SubWord for AES-256
      temp = bytes([S_BOX[b] for b in temp])
    w.append(bytes([w[i - nk][j] ^ temp[j] for j in range(4)]))

  # Flatten to list of bytes
  expanded = []
  for word in w:
    expanded.extend(word)
  return expanded


def _encrypt_block(block: bytes, expanded_key: list[int], nr: int) -> bytes:
  """
  Encrypt a single 16-byte block.

  Args:
      block: The 16-byte plaintext block.
      expanded_key: The expanded key schedule.
      nr: Number of rounds (10 for AES-128, 12 for AES-192, 14 for AES-256).

  Returns:
      The 16-byte ciphertext block.
  """
  state = bytearray(block)

  # Initial round
  add_round_key(state, bytes(expanded_key[0:16]))

  # Main rounds
  for round_num in range(1, nr):
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, bytes(expanded_key[round_num * 16 : (round_num + 1) * 16]))

  # Final round (no MixColumns)
  sub_bytes(state)
  shift_rows(state)
  add_round_key(state, bytes(expanded_key[nr * 16 : (nr + 1) * 16]))

  return bytes(state)


def _decrypt_block(block: bytes, expanded_key: list[int], nr: int) -> bytes:
  """
  Decrypt a single 16-byte block.

  Args:
      block: The 16-byte ciphertext block.
      expanded_key: The expanded key schedule.
      nr: Number of rounds (10 for AES-128, 12 for AES-192, 14 for AES-256).

  Returns:
      The 16-byte plaintext block.
  """
  state = bytearray(block)

  # Initial round
  add_round_key(state, bytes(expanded_key[nr * 16 : (nr + 1) * 16]))

  # Main rounds (in reverse)
  for round_num in range(nr - 1, 0, -1):
    shift_rows(state, inv=True)
    sub_bytes(state, inv=True)
    add_round_key(state, bytes(expanded_key[round_num * 16 : (round_num + 1) * 16]))
    mix_columns(state, inv=True)

  # Final round
  shift_rows(state, inv=True)
  sub_bytes(state, inv=True)
  add_round_key(state, bytes(expanded_key[0:16]))

  return bytes(state)


def _get_key_params(key: bytes) -> tuple[int, int]:
  """
  Get key parameters (Nk, Nr) based on key length.

  Args:
      key: The cipher key.

  Returns:
      Tuple of (nk, nr) where nk is key length in words and nr is number of rounds.
  """
  key_len = len(key)
  if key_len == 16:
    return 4, 10  # AES-128
  if key_len == 24:
    return 6, 12  # AES-192
  if key_len == 32:
    return 8, 14  # AES-256
  msg = f"Invalid key length: {key_len}. Must be 16, 24, or 32 bytes."
  raise ValueError(msg)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
  """
  Apply PKCS7 padding to data.

  Args:
      data: The data to pad.
      block_size: The block size (default 16 for AES).

  Returns:
      The padded data.
  """
  padding_len = block_size - (len(data) % block_size)
  if padding_len == 0:
    padding_len = block_size
  return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
  """
  Remove PKCS7 padding from data.

  Args:
      data: The padded data.
      block_size: The block size (default 16 for AES).

  Returns:
      The unpadded data.

  Raises:
      ValueError: If padding is invalid.
  """
  if not data:
    msg = "Empty data"
    raise ValueError(msg)
  padding_len = data[-1]
  if padding_len < 1 or padding_len > block_size:
    msg = f"Invalid padding length: {padding_len}"
    raise ValueError(msg)
  if len(data) < padding_len:
    msg = "Data too short for padding"
    raise ValueError(msg)
  # Verify all padding bytes
  for i in range(1, padding_len + 1):
    if data[-i] != padding_len:
      msg = "Invalid padding bytes"
      raise ValueError(msg)
  return data[:-padding_len]


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
  """
  Encrypt data using AES in ECB mode.

  Args:
      plaintext: The data to encrypt (will be PKCS7 padded).
      key: The encryption key (16, 24, or 32 bytes).

  Returns:
      The encrypted ciphertext.
  """
  _nk, nr = _get_key_params(key)
  expanded_key = key_expansion(key)

  padded = pkcs7_pad(plaintext)
  ciphertext = bytearray()

  for i in range(0, len(padded), 16):
    block = padded[i : i + 16]
    ciphertext.extend(_encrypt_block(block, expanded_key, nr))

  return bytes(ciphertext)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
  """
  Decrypt data using AES in ECB mode.

  Args:
      ciphertext: The data to decrypt (must be multiple of 16 bytes).
      key: The encryption key (16, 24, or 32 bytes).

  Returns:
      The decrypted plaintext (PKCS7 padding removed).
  """
  if len(ciphertext) % 16 != 0:
    msg = "Ciphertext length must be a multiple of 16"
    raise ValueError(msg)

  _nk, nr = _get_key_params(key)
  expanded_key = key_expansion(key)

  plaintext = bytearray()

  for i in range(0, len(ciphertext), 16):
    block = ciphertext[i : i + 16]
    plaintext.extend(_decrypt_block(block, expanded_key, nr))

  return pkcs7_unpad(bytes(plaintext))


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
  """
  Encrypt data using AES in CBC mode.

  Args:
      plaintext: The data to encrypt (will be PKCS7 padded).
      key: The encryption key (16, 24, or 32 bytes).
      iv: The initialization vector (16 bytes).

  Returns:
      The encrypted ciphertext.
  """
  if len(iv) != 16:
    msg = "IV must be 16 bytes"
    raise ValueError(msg)

  _nk, nr = _get_key_params(key)
  expanded_key = key_expansion(key)

  padded = pkcs7_pad(plaintext)
  ciphertext = bytearray()
  prev_block = iv

  for i in range(0, len(padded), 16):
    block = padded[i : i + 16]
    # XOR with previous ciphertext block (or IV for first block)
    xored = bytes([block[j] ^ prev_block[j] for j in range(16)])
    encrypted = _encrypt_block(xored, expanded_key, nr)
    ciphertext.extend(encrypted)
    prev_block = encrypted

  return bytes(ciphertext)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
  """
  Decrypt data using AES in CBC mode.

  Args:
      ciphertext: The data to decrypt (must be multiple of 16 bytes).
      key: The encryption key (16, 24, or 32 bytes).
      iv: The initialization vector (16 bytes).

  Returns:
      The decrypted plaintext (PKCS7 padding removed).
  """
  if len(ciphertext) % 16 != 0:
    msg = "Ciphertext length must be a multiple of 16"
    raise ValueError(msg)
  if len(iv) != 16:
    msg = "IV must be 16 bytes"
    raise ValueError(msg)

  _nk, nr = _get_key_params(key)
  expanded_key = key_expansion(key)

  plaintext = bytearray()
  prev_block = iv

  for i in range(0, len(ciphertext), 16):
    block = ciphertext[i : i + 16]
    decrypted = _decrypt_block(block, expanded_key, nr)
    # XOR with previous ciphertext block (or IV for first block)
    xored = bytes([decrypted[j] ^ prev_block[j] for j in range(16)])
    plaintext.extend(xored)
    prev_block = block

  return pkcs7_unpad(bytes(plaintext))


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
  """
  Encrypt or decrypt data using AES in CTR mode.

  CTR mode is symmetric - encryption and decryption use the same operation.

  Args:
      data: The data to encrypt or decrypt.
      key: The encryption key (16, 24, or 32 bytes).
      nonce: The nonce/IV (16 bytes total: 8-byte nonce + 8-byte counter,
             or any 16-byte value where the last 8 bytes form the counter).

  Returns:
      The encrypted or decrypted data.
  """
  if len(nonce) != 16:
    msg = "Nonce must be 16 bytes"
    raise ValueError(msg)

  _nk, nr = _get_key_params(key)
  expanded_key = key_expansion(key)

  result = bytearray()
  counter = int.from_bytes(nonce[8:], "big")
  nonce_prefix = nonce[:8]

  for i in range(0, len(data), 16):
    # Create counter block
    counter_block = nonce_prefix + counter.to_bytes(8, "big")
    keystream = _encrypt_block(counter_block, expanded_key, nr)

    # XOR with plaintext/ciphertext
    block = data[i : i + 16]
    for j in range(len(block)):
      result.append(block[j] ^ keystream[j])

    counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF

  return bytes(result)


def aes_encrypt(
  plaintext: bytes,
  key: bytes,
  mode: Literal["ecb", "cbc", "ctr"] = "ecb",
  iv: bytes | None = None,
) -> bytes:
  """
  Encrypt data using AES.

  Args:
      plaintext: The data to encrypt.
      key: The encryption key (16, 24, or 32 bytes).
      mode: The encryption mode ('ecb', 'cbc', or 'ctr').
      iv: The initialization vector (required for CBC, optional for others).
          For CTR mode, this is the nonce (16 bytes).

  Returns:
      The encrypted ciphertext.
  """
  if mode == "ecb":
    return aes_ecb_encrypt(plaintext, key)
  if mode == "cbc":
    if iv is None:
      msg = "IV is required for CBC mode"
      raise ValueError(msg)
    return aes_cbc_encrypt(plaintext, key, iv)
  if mode == "ctr":
    if iv is None:
      msg = "Nonce is required for CTR mode"
      raise ValueError(msg)
    return aes_ctr_crypt(plaintext, key, iv)
  msg = f"Unsupported mode: {mode}"
  raise ValueError(msg)


def aes_decrypt(
  ciphertext: bytes,
  key: bytes,
  mode: Literal["ecb", "cbc", "ctr"] = "ecb",
  iv: bytes | None = None,
) -> bytes:
  """
  Decrypt data using AES.

  Args:
      ciphertext: The data to decrypt.
      key: The encryption key (16, 24, or 32 bytes).
      mode: The encryption mode ('ecb', 'cbc', or 'ctr').
      iv: The initialization vector (required for CBC, optional for others).
          For CTR mode, this is the nonce (16 bytes).

  Returns:
      The decrypted plaintext.
  """
  if mode == "ecb":
    return aes_ecb_decrypt(ciphertext, key)
  if mode == "cbc":
    if iv is None:
      msg = "IV is required for CBC mode"
      raise ValueError(msg)
    return aes_cbc_decrypt(ciphertext, key, iv)
  if mode == "ctr":
    if iv is None:
      msg = "Nonce is required for CTR mode"
      raise ValueError(msg)
    return aes_ctr_crypt(ciphertext, key, iv)
  msg = f"Unsupported mode: {mode}"
  raise ValueError(msg)


if __name__ == "__main__":
  # Test vectors
  key = b"sxyz.blog foobar"
  plaintext = b"Gonna find the answer, how to clear this up"

  # ECB mode test
  enc = aes_ecb_encrypt(plaintext, key)
  dec = aes_ecb_decrypt(enc, key)
  print("ECB Encrypted:", enc.hex())
  print("ECB Decrypted:", dec)

  # CBC mode test
  iv = b"1234567890123456"
  enc_cbc = aes_cbc_encrypt(plaintext, key, iv)
  dec_cbc = aes_cbc_decrypt(enc_cbc, key, iv)
  print("CBC Encrypted:", enc_cbc.hex())
  print("CBC Decrypted:", dec_cbc)

  # CTR mode test
  nonce = b"1234567890123456"
  enc_ctr = aes_ctr_crypt(plaintext, key, nonce)
  dec_ctr = aes_ctr_crypt(enc_ctr, key, nonce)
  print("CTR Encrypted:", enc_ctr.hex())
  print("CTR Decrypted:", dec_ctr)
