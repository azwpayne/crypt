"""Pure Python implementation of PRESENT lightweight block cipher.

PRESENT is an ultra-lightweight block cipher designed for constrained devices.
It was designed by Bogdanov et al. and published in 2007.
- 64-bit block size
- 80 or 128-bit key
- 31 rounds
- SP-network structure

This implementation is for educational purposes only.
"""

from __future__ import annotations

from typing import Final

# PRESENT S-box (4-bit to 4-bit)
SBOX: Final[tuple[int, ...]] = (
  0xC,
  0x5,
  0x6,
  0xB,
  0x9,
  0x0,
  0xA,
  0xD,
  0x3,
  0xE,
  0xF,
  0x8,
  0x4,
  0x7,
  0x1,
  0x2,
)

# Inverse S-box
INV_SBOX: Final[tuple[int, ...]] = (
  0x5,
  0xE,
  0xF,
  0x8,
  0xC,
  0x1,
  0x2,
  0xD,
  0xB,
  0x4,
  0x6,
  0x3,
  0x0,
  0x7,
  0x9,
  0xA,
)

# P-layer permutation (position i moves to position P_LAYER[i])
P_LAYER: Final[tuple[int, ...]] = (
  0,
  16,
  32,
  48,
  1,
  17,
  33,
  49,
  2,
  18,
  34,
  50,
  3,
  19,
  35,
  51,
  4,
  20,
  36,
  52,
  5,
  21,
  37,
  53,
  6,
  22,
  38,
  54,
  7,
  23,
  39,
  55,
  8,
  24,
  40,
  56,
  9,
  25,
  41,
  57,
  10,
  26,
  42,
  58,
  11,
  27,
  43,
  59,
  12,
  28,
  44,
  60,
  13,
  29,
  45,
  61,
  14,
  30,
  46,
  62,
  15,
  31,
  47,
  63,
)

# Round constants (RC[i] for round i, where i starts at 0)
RC: Final[tuple[int, ...]] = (
  0x01,
  0x03,
  0x07,
  0x0F,
  0x1F,
  0x3E,
  0x3D,
  0x3B,
  0x37,
  0x2F,
  0x1E,
  0x3C,
  0x39,
  0x33,
  0x27,
  0x0E,
  0x1D,
  0x3A,
  0x35,
  0x2B,
  0x16,
  0x2C,
  0x18,
  0x30,
  0x21,
  0x02,
  0x05,
  0x0B,
  0x17,
  0x2E,
  0x1C,
  0x38,
)

BLOCK_SIZE: Final[int] = 8  # 64 bits


def _apply_sbox(value: int) -> int:
  """Apply S-box to 64-bit value (16 nibbles in parallel)."""
  result = 0
  for i in range(16):
    nibble = (value >> (4 * i)) & 0xF
    result |= SBOX[nibble] << (4 * i)
  return result


def _apply_inv_sbox(value: int) -> int:
  """Apply inverse S-box to 64-bit value."""
  result = 0
  for i in range(16):
    nibble = (value >> (4 * i)) & 0xF
    result |= INV_SBOX[nibble] << (4 * i)
  return result


def _apply_player(value: int) -> int:
  """Apply P-layer permutation to 64-bit value."""
  result = 0
  for i in range(64):
    bit = (value >> i) & 1
    result |= bit << P_LAYER[i]
  return result


def _apply_inv_player(value: int) -> int:
  """Apply inverse P-layer permutation."""
  result = 0
  for i in range(64):
    bit = (value >> P_LAYER[i]) & 1
    result |= bit << i
  return result


def key_schedule_80(key: bytes) -> list[int]:
  """Generate 32 64-bit round keys from 80-bit key.

  Args:
      key: 10-byte (80-bit) key

  Returns:
      List of 32 round keys
  """
  if len(key) != 10:
    msg = f"Key must be 10 bytes for 80-bit mode, got {len(key)}"
    raise ValueError(msg)

  # Initialize key state
  key_state = int.from_bytes(key, "big")
  round_keys = []

  for i in range(32):
    # Extract round key (leftmost 64 bits)
    round_key = (key_state >> 16) & 0xFFFFFFFFFFFFFFFF
    round_keys.append(round_key)

    # Key schedule update
    # 1. Rotate left by 61
    key_state = ((key_state << 61) | (key_state >> 19)) & ((1 << 80) - 1)
    # 2. Apply S-box to leftmost 4 bits
    left_nibble = (key_state >> 76) & 0xF
    new_nibble = SBOX[left_nibble]
    key_state = (key_state & ~((1 << 80) - (1 << 76))) | (new_nibble << 76)
    # 3. XOR with round counter
    key_state ^= RC[i] << 15

  return round_keys


def key_schedule_128(key: bytes) -> list[int]:
  """Generate 32 64-bit round keys from 128-bit key.

  Args:
      key: 16-byte (128-bit) key

  Returns:
      List of 32 round keys
  """
  if len(key) != 16:
    msg = f"Key must be 16 bytes for 128-bit mode, got {len(key)}"
    raise ValueError(msg)

  # Initialize key state
  key_state = int.from_bytes(key, "big")
  round_keys = []

  for i in range(32):
    # Extract round key (leftmost 64 bits)
    round_key = (key_state >> 64) & 0xFFFFFFFFFFFFFFFF
    round_keys.append(round_key)

    # Key schedule update
    # 1. Rotate left by 61
    key_state = ((key_state << 61) | (key_state >> 67)) & ((1 << 128) - 1)
    # 2. Apply S-box to leftmost 4 bits
    left_nibble = (key_state >> 124) & 0xF
    new_nibble = SBOX[left_nibble]
    key_state = (key_state & ~((1 << 128) - (1 << 124))) | (new_nibble << 124)
    # 3. Apply S-box to bits 123-120
    second_nibble = (key_state >> 120) & 0xF
    new_second = SBOX[second_nibble]
    key_state = (key_state & ~(0xF << 120)) | (new_second << 120)
    # 4. XOR with round counter
    key_state ^= RC[i] << 62

  return round_keys


def key_schedule(key: bytes) -> list[int]:
  """Generate 32 64-bit round keys from key.

  Supports 80-bit (10 bytes) or 128-bit (16 bytes) keys.

  Args:
      key: 10 or 16 byte key

  Returns:
      List of 32 round keys
  """
  if len(key) == 10:
    return key_schedule_80(key)
  if len(key) == 16:
    return key_schedule_128(key)
  msg = f"Key must be 10 or 16 bytes, got {len(key)}"
  raise ValueError(msg)


def encrypt_block(block: bytes, key: bytes) -> bytes:
  """Encrypt single 8-byte block with PRESENT.

  Args:
      block: 8-byte plaintext
      key: 10-byte (80-bit) or 16-byte (128-bit) key

  Returns:
      8-byte ciphertext
  """
  if len(block) != BLOCK_SIZE:
    msg = f"Block must be {BLOCK_SIZE} bytes, got {len(block)}"
    raise ValueError(msg)

  round_keys = key_schedule(key)

  # Convert to 64-bit integer (big endian)
  state = int.from_bytes(block, "big")

  # 31 rounds
  for i in range(31):
    # AddRoundKey (XOR)
    state ^= round_keys[i]
    # sBoxLayer
    state = _apply_sbox(state)
    # pLayer
    state = _apply_player(state)

  # Final AddRoundKey
  state ^= round_keys[31]

  return state.to_bytes(8, "big")


def decrypt_block(block: bytes, key: bytes) -> bytes:
  """Decrypt single 8-byte block with PRESENT.

  Args:
      block: 8-byte ciphertext
      key: 10-byte (80-bit) or 16-byte (128-bit) key

  Returns:
      8-byte plaintext
  """
  if len(block) != BLOCK_SIZE:
    msg = f"Block must be {BLOCK_SIZE} bytes, got {len(block)}"
    raise ValueError(msg)

  round_keys = key_schedule(key)

  # Convert to 64-bit integer (big endian)
  state = int.from_bytes(block, "big")

  # Final AddRoundKey (reverse)
  state ^= round_keys[31]

  # 31 rounds in reverse
  for i in range(30, -1, -1):
    # Inverse pLayer
    state = _apply_inv_player(state)
    # Inverse sBoxLayer
    state = _apply_inv_sbox(state)
    # AddRoundKey
    state ^= round_keys[i]

  return state.to_bytes(8, "big")


# PKCS7 padding helpers
def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
  """Pad data using PKCS7."""
  padding_len = block_size - (len(data) % block_size)
  return data + bytes([padding_len] * padding_len)


def _pkcs7_unpad(data: bytes) -> bytes:
  """Remove PKCS7 padding."""
  if not data:
    return data
  padding_len = data[-1]
  if padding_len > len(data) or padding_len == 0:
    return data
  # Verify padding
  for i in range(1, padding_len + 1):
    if data[-i] != padding_len:
      return data
  return data[:-padding_len]


def present_ecb_encrypt(data: bytes, key: bytes) -> bytes:
  """Encrypt data using PRESENT in ECB mode."""
  padded = _pkcs7_pad(data, BLOCK_SIZE)
  result = b""
  for i in range(0, len(padded), BLOCK_SIZE):
    result += encrypt_block(padded[i : i + BLOCK_SIZE], key)
  return result


def present_ecb_decrypt(data: bytes, key: bytes) -> bytes:
  """Decrypt data using PRESENT in ECB mode."""
  result = b""
  for i in range(0, len(data), BLOCK_SIZE):
    result += decrypt_block(data[i : i + BLOCK_SIZE], key)
  return _pkcs7_unpad(result)


def present_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
  """Encrypt data using PRESENT in CBC mode."""
  if len(iv) != BLOCK_SIZE:
    msg = f"IV must be {BLOCK_SIZE} bytes"
    raise ValueError(msg)

  padded = _pkcs7_pad(data, BLOCK_SIZE)
  result = b""
  prev = iv

  for i in range(0, len(padded), BLOCK_SIZE):
    block = padded[i : i + BLOCK_SIZE]
    xored = bytes(a ^ b for a, b in zip(block, prev, strict=False))
    encrypted = encrypt_block(xored, key)
    result += encrypted
    prev = encrypted

  return result


def present_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
  """Decrypt data using PRESENT in CBC mode."""
  if len(iv) != BLOCK_SIZE:
    msg = f"IV must be {BLOCK_SIZE} bytes"
    raise ValueError(msg)

  result = b""
  prev = iv

  for i in range(0, len(data), BLOCK_SIZE):
    block = data[i : i + BLOCK_SIZE]
    decrypted = decrypt_block(block, key)
    xored = bytes(a ^ b for a, b in zip(decrypted, prev, strict=False))
    result += xored
    prev = block

  return _pkcs7_unpad(result)
