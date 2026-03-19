# @author  : azwpayne(https://github.com/azwpayne)
# @name    : scrypt.py
# @time    : 2026/03/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Scrypt Key Derivation Function (RFC 7914)
"""
Scrypt is a memory-hard key derivation function designed to be resistant
to hardware brute-force attacks. It is used in cryptocurrencies like
Litecoin and Dogecoin, and in password hashing.

Reference: RFC 7914 - The scrypt Password-Based Key Derivation Function
"""

import hashlib
import struct


def _salsa20_8_core(input_bytes: bytes) -> bytes:
  """
  Salsa20/8 core function - 8 rounds of Salsa20.
  This is used in BlockMix.
  """
  # Convert bytes to 16 32-bit words (little-endian)
  x = list(struct.unpack("<16I", input_bytes))
  orig_x = x.copy()

  # 8 rounds of Salsa20 (4 double rounds)
  for _ in range(4):
    # Column round
    x[4] ^= ((x[0] + x[12]) & 0xFFFFFFFF) << 7 | ((x[0] + x[12]) & 0xFFFFFFFF) >> 25
    x[8] ^= ((x[4] + x[0]) & 0xFFFFFFFF) << 9 | ((x[4] + x[0]) & 0xFFFFFFFF) >> 23
    x[12] ^= ((x[8] + x[4]) & 0xFFFFFFFF) << 13 | ((x[8] + x[4]) & 0xFFFFFFFF) >> 19
    x[0] ^= ((x[12] + x[8]) & 0xFFFFFFFF) << 18 | ((x[12] + x[8]) & 0xFFFFFFFF) >> 14

    x[9] ^= ((x[5] + x[1]) & 0xFFFFFFFF) << 7 | ((x[5] + x[1]) & 0xFFFFFFFF) >> 25
    x[13] ^= ((x[9] + x[5]) & 0xFFFFFFFF) << 9 | ((x[9] + x[5]) & 0xFFFFFFFF) >> 23
    x[1] ^= ((x[13] + x[9]) & 0xFFFFFFFF) << 13 | ((x[13] + x[9]) & 0xFFFFFFFF) >> 19
    x[5] ^= ((x[1] + x[13]) & 0xFFFFFFFF) << 18 | ((x[1] + x[13]) & 0xFFFFFFFF) >> 14

    x[14] ^= ((x[10] + x[6]) & 0xFFFFFFFF) << 7 | ((x[10] + x[6]) & 0xFFFFFFFF) >> 25
    x[2] ^= ((x[14] + x[10]) & 0xFFFFFFFF) << 9 | ((x[14] + x[10]) & 0xFFFFFFFF) >> 23
    x[6] ^= ((x[2] + x[14]) & 0xFFFFFFFF) << 13 | ((x[2] + x[14]) & 0xFFFFFFFF) >> 19
    x[10] ^= ((x[6] + x[2]) & 0xFFFFFFFF) << 18 | ((x[6] + x[2]) & 0xFFFFFFFF) >> 14

    x[3] ^= ((x[15] + x[11]) & 0xFFFFFFFF) << 7 | ((x[15] + x[11]) & 0xFFFFFFFF) >> 25
    x[7] ^= ((x[3] + x[15]) & 0xFFFFFFFF) << 9 | ((x[3] + x[15]) & 0xFFFFFFFF) >> 23
    x[11] ^= ((x[7] + x[3]) & 0xFFFFFFFF) << 13 | ((x[7] + x[3]) & 0xFFFFFFFF) >> 19
    x[15] ^= ((x[11] + x[7]) & 0xFFFFFFFF) << 18 | ((x[11] + x[7]) & 0xFFFFFFFF) >> 14

    # Row round
    x[1] ^= ((x[0] + x[3]) & 0xFFFFFFFF) << 7 | ((x[0] + x[3]) & 0xFFFFFFFF) >> 25
    x[2] ^= ((x[1] + x[0]) & 0xFFFFFFFF) << 9 | ((x[1] + x[0]) & 0xFFFFFFFF) >> 23
    x[3] ^= ((x[2] + x[1]) & 0xFFFFFFFF) << 13 | ((x[2] + x[1]) & 0xFFFFFFFF) >> 19
    x[0] ^= ((x[3] + x[2]) & 0xFFFFFFFF) << 18 | ((x[3] + x[2]) & 0xFFFFFFFF) >> 14

    x[6] ^= ((x[5] + x[4]) & 0xFFFFFFFF) << 7 | ((x[5] + x[4]) & 0xFFFFFFFF) >> 25
    x[7] ^= ((x[6] + x[5]) & 0xFFFFFFFF) << 9 | ((x[6] + x[5]) & 0xFFFFFFFF) >> 23
    x[4] ^= ((x[7] + x[6]) & 0xFFFFFFFF) << 13 | ((x[7] + x[6]) & 0xFFFFFFFF) >> 19
    x[5] ^= ((x[4] + x[7]) & 0xFFFFFFFF) << 18 | ((x[4] + x[7]) & 0xFFFFFFFF) >> 14

    x[11] ^= ((x[10] + x[9]) & 0xFFFFFFFF) << 7 | ((x[10] + x[9]) & 0xFFFFFFFF) >> 25
    x[8] ^= ((x[11] + x[10]) & 0xFFFFFFFF) << 9 | ((x[11] + x[10]) & 0xFFFFFFFF) >> 23
    x[9] ^= ((x[8] + x[11]) & 0xFFFFFFFF) << 13 | ((x[8] + x[11]) & 0xFFFFFFFF) >> 19
    x[10] ^= ((x[9] + x[8]) & 0xFFFFFFFF) << 18 | ((x[9] + x[8]) & 0xFFFFFFFF) >> 14

    x[12] ^= ((x[15] + x[14]) & 0xFFFFFFFF) << 7 | ((x[15] + x[14]) & 0xFFFFFFFF) >> 25
    x[13] ^= ((x[12] + x[15]) & 0xFFFFFFFF) << 9 | ((x[12] + x[15]) & 0xFFFFFFFF) >> 23
    x[14] ^= ((x[13] + x[12]) & 0xFFFFFFFF) << 13 | ((x[13] + x[12]) & 0xFFFFFFFF) >> 19
    x[15] ^= ((x[14] + x[13]) & 0xFFFFFFFF) << 18 | ((x[14] + x[13]) & 0xFFFFFFFF) >> 14

  # Add original values
  return struct.pack("<16I", *[(x[i] + orig_x[i]) & 0xFFFFFFFF for i in range(16)])


def _blockmix(input_bytes: bytes, r: int) -> bytes:
  """
  BlockMix algorithm from scrypt.
  Input: B (2r * 64 bytes)
  Output: B' (2r * 64 bytes)
  """
  # X = B[2r-1]
  x = input_bytes[(2 * r - 1) * 64 : 2 * r * 64]
  y = bytearray()

  for i in range(2 * r):
    # X = H(X xor B[i])
    block = input_bytes[i * 64 : (i + 1) * 64]
    x = _salsa20_8_core(bytes(a ^ b for a, b in zip(x, block, strict=False)))
    y.extend(x)

  # Permute: even blocks first, then odd blocks
  output = bytearray(len(input_bytes))
  for i in range(r):
    output[i * 64 : (i + 1) * 64] = y[(2 * i) * 64 : (2 * i + 1) * 64]
    output[(r + i) * 64 : (r + i + 1) * 64] = y[(2 * i + 1) * 64 : (2 * i + 2) * 64]

  return bytes(output)


def _smix(b: bytes, n: int, r: int) -> bytes:
  """
  SMix algorithm from scrypt.
  Mixes the input B using N iterations and r blocks.
  """
  x = b[:]
  v = []

  # First phase: write to V
  for _i in range(n):
    v.append(x)
    x = _blockmix(x, r)

  # Second phase: random reads from V
  for _i in range(n):
    j = int.from_bytes(x[(2 * r - 1) * 64 : 2 * r * 64], "little") % n
    x = _blockmix(bytes(a ^ b for a, b in zip(x, v[j], strict=False)), r)

  return x


def scrypt(
  password: str | bytes,
  salt: str | bytes,
  *,
  n: int = 2**14,
  r: int = 8,
  p: int = 1,
  **kwargs: int,
) -> bytes:
  """
  Scrypt key derivation function (RFC 7914).

  Args:
      password: The password to derive key from
      salt: A random salt (should be unique per password)
      n: CPU/memory cost parameter (must be power of 2, > 1)
      r: Block size parameter
      p: Parallelization parameter
      dklen: Desired length of derived key in bytes

  Returns:
      Derived key as bytes

  Raises:
      ValueError: If parameters are invalid
  """
  dklen: int = kwargs.get("dklen", 64)
  if isinstance(password, str):
    password = password.encode("utf-8")
  if isinstance(salt, str):
    salt = salt.encode("utf-8")

  # Validate parameters
  if n <= 1 or (n & (n - 1)) != 0:
    msg = "N must be a power of 2 greater than 1"
    raise ValueError(msg)
  if r < 1:
    msg = "r must be positive"
    raise ValueError(msg)
  if p < 1:
    msg = "p must be positive"
    raise ValueError(msg)
  if n >= 2 ** (128 * r // 8):
    msg = "N is too large for the given r"
    raise ValueError(msg)

  # Step 1: Generate initial key using PBKDF2
  b = hashlib.pbkdf2_hmac("sha256", password, salt, 1, p * 128 * r)

  # Step 2: Mix each block using SMix
  for i in range(p):
    b_i = b[i * 128 * r : (i + 1) * 128 * r]
    b_i = _smix(b_i, n, r)
    b = b[: i * 128 * r] + b_i + b[(i + 1) * 128 * r :]

  # Step 3: Final PBKDF2
  return hashlib.pbkdf2_hmac("sha256", password, b, 1, dklen)
