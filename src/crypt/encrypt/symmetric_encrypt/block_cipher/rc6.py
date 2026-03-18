"""Pure Python implementation of RC6 block cipher.

RC6 is a symmetric key block cipher designed by Rivest, Robshaw, Sidney, and Yin.
It was an AES finalist. RC6 has a block size of 128 bits and supports variable
key sizes. It uses data-dependent rotations and 4 working registers.

This implementation defaults to 128-bit blocks, 20 rounds, and 32-byte keys.

This implementation is for educational purposes only.
"""

from __future__ import annotations

from typing import Final

# RC6 constants
P32: Final[int] = 0xB7E15163  # Magic constant derived from e
Q32: Final[int] = 0x9E3779B9  # Magic constant derived from golden ratio

WORD_SIZE: Final[int] = 32
BLOCK_SIZE: Final[int] = 16  # 128 bits = 16 bytes
ROUNDS: Final[int] = 20
KEY_SIZE: Final[int] = 32
MASK32: Final[int] = 0xFFFFFFFF
LG_W: Final[int] = 5  # log2(32) = 5


def _rotl(x: int, n: int) -> int:
  """32-bit left rotation."""
  n %= 32
  return ((x << n) | (x >> (32 - n))) & MASK32


def _rotr(x: int, n: int) -> int:
  """32-bit right rotation."""
  n %= 32
  return ((x >> n) | (x << (32 - n))) & MASK32


def key_schedule(key: bytes, rounds: int = ROUNDS) -> list[int]:
  """Generate RC6 round subkeys from key.

  Args:
      key: Variable length key (0-255 bytes)
      rounds: Number of rounds (default 20)

  Returns:
      List of 2*(rounds+2) 32-bit subkeys
  """
  key_len = len(key)

  # Convert key to word array L
  c = max(1, (key_len + 3) // 4)  # Number of words
  key_words = [0] * c

  for i in range(key_len - 1, -1, -1):
    key_words[i // 4] = (key_words[i // 4] << 8) | key[i]

  # Initialize S array with constants
  t = 2 * (rounds + 2)
  s_array = [0] * t
  s_array[0] = P32
  for i in range(1, t):
    s_array[i] = (s_array[i - 1] + Q32) & MASK32

  # Mix key into S
  i = j = 0
  a = b = 0
  for _ in range(3 * max(t, c)):
    a = s_array[i] = _rotl((s_array[i] + a + b) & MASK32, 3)
    b = key_words[j] = _rotl((key_words[j] + a + b) & MASK32, (a + b) % 32)
    i = (i + 1) % t
    j = (j + 1) % c

  return s_array


def encrypt_block(block: bytes, key: bytes, rounds: int = ROUNDS) -> bytes:
  """Encrypt single 16-byte block with RC6.

  Args:
      block: 16-byte plaintext
      key: Variable length key
      rounds: Number of rounds (default 20)

  Returns:
      16-byte ciphertext
  """
  if len(block) != BLOCK_SIZE:
    msg = f"Block must be {BLOCK_SIZE} bytes, got {len(block)}"
    raise ValueError(msg)

  s_array = key_schedule(key, rounds)

  # Split into four 32-bit words (little endian)
  a = int.from_bytes(block[0:4], "little")
  b = int.from_bytes(block[4:8], "little")
  c = int.from_bytes(block[8:12], "little")
  d = int.from_bytes(block[12:16], "little")

  # Initial whitening
  b = (b + s_array[0]) & MASK32
  d = (d + s_array[1]) & MASK32

  # Rounds
  for i in range(1, rounds + 1):
    t = _rotl(b * (2 * b + 1) & MASK32, LG_W)
    u = _rotl(d * (2 * d + 1) & MASK32, LG_W)
    a = (_rotl(a ^ t, u % 32) + s_array[2 * i]) & MASK32
    c = (_rotl(c ^ u, t % 32) + s_array[2 * i + 1]) & MASK32
    a, b, c, d = b, c, d, a

  # Final whitening
  a = (a + s_array[2 * rounds + 2]) & MASK32
  c = (c + s_array[2 * rounds + 3]) & MASK32

  # Combine result (little endian)
  return (
    a.to_bytes(4, "little")
    + b.to_bytes(4, "little")
    + c.to_bytes(4, "little")
    + d.to_bytes(4, "little")
  )


def decrypt_block(block: bytes, key: bytes, rounds: int = ROUNDS) -> bytes:
  """Decrypt single 16-byte block with RC6.

  Args:
      block: 16-byte ciphertext
      key: Variable length key
      rounds: Number of rounds (default 20)

  Returns:
      16-byte plaintext
  """
  if len(block) != BLOCK_SIZE:
    msg = f"Block must be {BLOCK_SIZE} bytes, got {len(block)}"
    raise ValueError(msg)

  s_array = key_schedule(key, rounds)

  # Split into four 32-bit words (little endian)
  a = int.from_bytes(block[0:4], "little")
  b = int.from_bytes(block[4:8], "little")
  c = int.from_bytes(block[8:12], "little")
  d = int.from_bytes(block[12:16], "little")

  # Reverse final whitening
  c = (c - s_array[2 * rounds + 3]) & MASK32
  a = (a - s_array[2 * rounds + 2]) & MASK32

  # Reverse rounds
  for i in range(rounds, 0, -1):
    a, b, c, d = d, a, b, c
    u = _rotl(d * (2 * d + 1) & MASK32, LG_W)
    t = _rotl(b * (2 * b + 1) & MASK32, LG_W)
    c = _rotr((c - s_array[2 * i + 1]) & MASK32, t % 32) ^ u
    a = _rotr((a - s_array[2 * i]) & MASK32, u % 32) ^ t

  # Reverse initial whitening
  d = (d - s_array[1]) & MASK32
  b = (b - s_array[0]) & MASK32

  # Combine result (little endian)
  return (
    a.to_bytes(4, "little")
    + b.to_bytes(4, "little")
    + c.to_bytes(4, "little")
    + d.to_bytes(4, "little")
  )


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


def rc6_ecb_encrypt(data: bytes, key: bytes, rounds: int = ROUNDS) -> bytes:
  """Encrypt data using RC6 in ECB mode."""
  padded = _pkcs7_pad(data, BLOCK_SIZE)
  result = b""
  for i in range(0, len(padded), BLOCK_SIZE):
    result += encrypt_block(padded[i : i + BLOCK_SIZE], key, rounds)
  return result


def rc6_ecb_decrypt(data: bytes, key: bytes, rounds: int = ROUNDS) -> bytes:
  """Decrypt data using RC6 in ECB mode."""
  result = b""
  for i in range(0, len(data), BLOCK_SIZE):
    result += decrypt_block(data[i : i + BLOCK_SIZE], key, rounds)
  return _pkcs7_unpad(result)


def rc6_cbc_encrypt(data: bytes, key: bytes, iv: bytes, rounds: int = ROUNDS) -> bytes:
  """Encrypt data using RC6 in CBC mode."""
  if len(iv) != BLOCK_SIZE:
    msg = f"IV must be {BLOCK_SIZE} bytes"
    raise ValueError(msg)

  padded = _pkcs7_pad(data, BLOCK_SIZE)
  result = b""
  prev = iv

  for i in range(0, len(padded), BLOCK_SIZE):
    block = padded[i : i + BLOCK_SIZE]
    xored = bytes(a ^ b for a, b in zip(block, prev, strict=False))
    encrypted = encrypt_block(xored, key, rounds)
    result += encrypted
    prev = encrypted

  return result


def rc6_cbc_decrypt(data: bytes, key: bytes, iv: bytes, rounds: int = ROUNDS) -> bytes:
  """Decrypt data using RC6 in CBC mode."""
  if len(iv) != BLOCK_SIZE:
    msg = f"IV must be {BLOCK_SIZE} bytes"
    raise ValueError(msg)

  result = b""
  prev = iv

  for i in range(0, len(data), BLOCK_SIZE):
    block = data[i : i + BLOCK_SIZE]
    decrypted = decrypt_block(block, key, rounds)
    xored = bytes(a ^ b for a, b in zip(decrypted, prev, strict=False))
    result += xored
    prev = block

  return _pkcs7_unpad(result)
