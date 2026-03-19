"""SHA-256 Hash Algorithm Implementation

Implements the SHA-256 (Secure Hash Algorithm) as defined in FIPS 180-4.
Produces a 256-bit (32-byte) hash value.

Features:
- FIPS 180-4 compliant
- Pure Python implementation
- Supports arbitrary length messages

Security Notes:
- SHA-256 produces a 256-bit (32-byte) hash
- Collision resistant (as of current knowledge)
- Suitable for digital signatures, message authentication,
  and other cryptographic applications
- Recommended for most new applications

References:
- FIPS 180-4: Secure Hash Standard (SHS)
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
"""

from __future__ import annotations

import struct

# Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
IV = (
  0x6A09E667,
  0xBB67AE85,
  0x3C6EF372,
  0xA54FF53A,
  0x510E527F,
  0x9B05688C,
  0x1F83D9AB,
  0x5BE0CD19,
)

# Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
K = (
  0x428A2F98,
  0x71374491,
  0xB5C0FBCF,
  0xE9B5DBA5,
  0x3956C25B,
  0x59F111F1,
  0x923F82A4,
  0xAB1C5ED5,
  0xD807AA98,
  0x12835B01,
  0x243185BE,
  0x550C7DC3,
  0x72BE5D74,
  0x80DEB1FE,
  0x9BDC06A7,
  0xC19BF174,
  0xE49B69C1,
  0xEFBE4786,
  0x0FC19DC6,
  0x240CA1CC,
  0x2DE92C6F,
  0x4A7484AA,
  0x5CB0A9DC,
  0x76F988DA,
  0x983E5152,
  0xA831C66D,
  0xB00327C8,
  0xBF597FC7,
  0xC6E00BF3,
  0xD5A79147,
  0x06CA6351,
  0x14292967,
  0x27B70A85,
  0x2E1B2138,
  0x4D2C6DFC,
  0x53380D13,
  0x650A7354,
  0x766A0ABB,
  0x81C2C92E,
  0x92722C85,
  0xA2BFE8A1,
  0xA81A664B,
  0xC24B8B70,
  0xC76C51A3,
  0xD192E819,
  0xD6990624,
  0xF40E3585,
  0x106AA070,
  0x19A4C116,
  0x1E376C08,
  0x2748774C,
  0x34B0BCB5,
  0x391C0CB3,
  0x4ED8AA4A,
  0x5B9CCA4F,
  0x682E6FF3,
  0x748F82EE,
  0x78A5636F,
  0x84C87814,
  0x8CC70208,
  0x90BEFFFA,
  0xA4506CEB,
  0xBEF9A3F7,
  0xC67178F2,
)


def _right_rotate(value: int, shift_bits: int) -> int:
  """Perform a right circular rotation on a 32-bit integer.

  Args:
      value: The 32-bit integer to rotate
      shift_bits: Number of bits to rotate right

  Returns:
      The rotated 32-bit integer
  """
  # Normalize shift to 0-31 range
  normalized_shift = shift_bits % 32
  if normalized_shift == 0:
    return value & 0xFFFFFFFF
  return ((value >> normalized_shift) | (value << (32 - normalized_shift))) & 0xFFFFFFFF


def sha256(data: bytes) -> str:
  """Compute SHA-256 hash of data.

  Implements the SHA-256 algorithm as specified in FIPS 180-4.
  Processes data in 512-bit blocks using 64 rounds of computation.

  Args:
      data: The data to hash as bytes

  Returns:
      The 64-character hexadecimal string representing the 32-byte hash

  Raises:
      TypeError: If data is not bytes-like

  Examples:
      >>> sha256(b"")
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      >>> sha256(b"abc")
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
      >>> sha256(b"hello world")
      'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
  """
  if not isinstance(data, bytes):
    msg = "data must be bytes"
    raise TypeError(msg)

  # Step 1: Pad the message
  original_byte_len = len(data)
  original_bit_len = original_byte_len * 8
  data += b"\x80"
  data += b"\x00" * ((56 - (original_byte_len + 1) % 64) % 64)
  data += struct.pack(">Q", original_bit_len)

  # Step 2: Parse message into 512-bit blocks
  blocks = [data[i : i + 64] for i in range(0, len(data), 64)]

  # Step 3: Initialize working variables from IV
  hash_pieces = list(IV)

  # Step 4: Process each block
  for block in blocks:
    # Prepare message schedule
    w = list(struct.unpack(">16L", block)) + [0] * 48

    for i in range(16, 64):
      s0 = _right_rotate(w[i - 15], 7) ^ _right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
      s1 = _right_rotate(w[i - 2], 17) ^ _right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

    # Initialize working variables
    a, b, c, d, e, f, g, h = hash_pieces

    # Main loop - 64 rounds
    for i in range(64):
      s1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
      ch = (e & f) ^ (~e & g)
      temp1 = (h + s1 + ch + K[i] + w[i]) & 0xFFFFFFFF

      s0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
      maj = (a & b) ^ (a & c) ^ (b & c)
      temp2 = (s0 + maj) & 0xFFFFFFFF

      # Update working variables
      h = g
      g = f
      f = e
      e = (d + temp1) & 0xFFFFFFFF
      d = c
      c = b
      b = a
      a = (temp1 + temp2) & 0xFFFFFFFF

    # Add compressed chunk to current hash value
    hash_pieces = [
      (x + y) & 0xFFFFFFFF
      for x, y in zip(hash_pieces, [a, b, c, d, e, f, g, h], strict=False)
    ]

  # Step 5: Produce final hash value (big-endian)
  return "".join(f"{piece:08x}" for piece in hash_pieces)


def sha256_bytes(data: bytes) -> bytes:
  """Compute SHA-256 hash and return raw bytes.

  Args:
      data: The data to hash as bytes

  Returns:
      The 32-byte hash digest as bytes

  Examples:
      >>> sha256_bytes(b"hello")
      b'\\x94\\xbd\\x27\\xb9\\x93\\x4d\\x3e\\x08\\xa5\\x2e\\x52\\xd7\\xda\\x7d\\xab\\xfa\\xc4\\x84\\xef\\xe3\\x7a\\x53\\x80\\xee\\x90\\x88\\xf7\\xac\\xe2\\xef\\xcd\\xe9'
  """
  hex_result = sha256(data)
  return bytes.fromhex(hex_result)


if __name__ == "__main__":
  # Test vectors from NIST
  print(sha256(b""))
  print(sha256(b"abc"))
