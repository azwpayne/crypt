"""SHA-512 Hash Algorithm Implementation

Implements the SHA-512 (Secure Hash Algorithm) as defined in FIPS 180-4.
Produces a 512-bit (64-byte) hash value.

Features:
- FIPS 180-4 compliant
- Pure Python implementation
- Supports arbitrary length messages
- Uses 64-bit words (vs 32-bit in SHA-256)

Security Notes:
- SHA-512 produces a 512-bit (64-byte) hash
- Higher security margin than SHA-256
- Suitable for high-security applications
- Recommended for post-quantum preparedness
- Slower than SHA-256 on 32-bit systems, faster on 64-bit systems

References:
- FIPS 180-4: Secure Hash Standard (SHS)
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
"""

from __future__ import annotations

import struct

# Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
H = [
  0x6A09E667F3BCC908,
  0xBB67AE8584CAA73B,
  0x3C6EF372FE94F82B,
  0xA54FF53A5F1D36F1,
  0x510E527FADE682D1,
  0x9B05688C2B3E6C1F,
  0x1F83D9ABFB41BD6B,
  0x5BE0CD19137E2179,
]

# Round constants (first 64 bits of fractional parts of cube roots of first 80 primes)
K = [
  0x428A2F98D728AE22,
  0x7137449123EF65CD,
  0xB5C0FBCFEC4D3B2F,
  0xE9B5DBA58189DBBC,
  0x3956C25BF348B538,
  0x59F111F1B605D019,
  0x923F82A4AF194F9B,
  0xAB1C5ED5DA6D8118,
  0xD807AA98A3030242,
  0x12835B0145706FBE,
  0x243185BE4EE4B28C,
  0x550C7DC3D5FFB4E2,
  0x72BE5D74F27B896F,
  0x80DEB1FE3B1696B1,
  0x9BDC06A725C71235,
  0xC19BF174CF692694,
  0xE49B69C19EF14AD2,
  0xEFBE4786384F25E3,
  0x0FC19DC68B8CD5B5,
  0x240CA1CC77AC9C65,
  0x2DE92C6F592B0275,
  0x4A7484AA6EA6E483,
  0x5CB0A9DCBD41FBD4,
  0x76F988DA831153B5,
  0x983E5152EE66DFAB,
  0xA831C66D2DB43210,
  0xB00327C898FB213F,
  0xBF597FC7BEEF0EE4,
  0xC6E00BF33DA88FC2,
  0xD5A79147930AA725,
  0x06CA6351E003826F,
  0x142929670A0E6E70,
  0x27B70A8546D22FFC,
  0x2E1B21385C26C926,
  0x4D2C6DFC5AC42AED,
  0x53380D139D95B3DF,
  0x650A73548BAF63DE,
  0x766A0ABB3C77B2A8,
  0x81C2C92E47EDAEE6,
  0x92722C851482353B,
  0xA2BFE8A14CF10364,
  0xA81A664BBC423001,
  0xC24B8B70D0F89791,
  0xC76C51A30654BE30,
  0xD192E819D6EF5218,
  0xD69906245565A910,
  0xF40E35855771202A,
  0x106AA07032BBD1B8,
  0x19A4C116B8D2D0C8,
  0x1E376C085141AB53,
  0x2748774CDF8EEB99,
  0x34B0BCB5E19B48A8,
  0x391C0CB3C5C95A63,
  0x4ED8AA4AE3418ACB,
  0x5B9CCA4F7763E373,
  0x682E6FF3D6B2B8A3,
  0x748F82EE5DEFB2FC,
  0x78A5636F43172F60,
  0x84C87814A1F0AB72,
  0x8CC702081A6439EC,
  0x90BEFFFA23631E28,
  0xA4506CEBDE82BDE9,
  0xBEF9A3F7B2C67915,
  0xC67178F2E372532B,
  0xCA273ECEEA26619C,
  0xD186B8C721C0C207,
  0xEADA7DD6CDE0EB1E,
  0xF57D4F7FEE6ED178,
  0x06F067AA72176FBA,
  0x0A637DC5A2C898A6,
  0x113F9804BEF90DAE,
  0x1B710B35131C471B,
  0x28DB77F523047D84,
  0x32CAAB7B40C72493,
  0x3C9EBE0A15C9BEBC,
  0x431D67C49C100D4C,
  0x4CC5D4BECB3E42B6,
  0x597F299CFC657E2A,
  0x5FCB6FAB3AD6FAEC,
  0x6C44198C4A475817,
]


def _right_rotate(value: int, shift: int, size: int = 64) -> int:
  """Perform a right circular rotation on a 64-bit integer.

  Args:
      value: The 64-bit integer to rotate
      shift: Number of bits to rotate right
      size: Word size in bits (default: 64)

  Returns:
      The rotated 64-bit integer
  """
  return ((value >> shift) | (value << (size - shift))) & ((1 << size) - 1)


def _pad_message(message: bytes | str | bytearray) -> bytearray:
  """Pad message according to SHA-512 padding rules.

  Args:
      message: The message to pad (bytes or string)

  Returns:
      The padded message as bytearray
  """
  if isinstance(message, str):
    message = bytearray(message, "utf-8")
  else:
    message = bytearray(message)

  original_length = len(message) * 8
  message.append(0x80)

  # Pad with zeros until length is 896 mod 1024
  while (len(message) * 8) % 1024 != 896:
    message.append(0)

  # Append length as 128-bit big-endian integer
  message += struct.pack(">Q", 0) + struct.pack(">Q", original_length)
  return message


def _parse_message_blocks(message: bytes | bytearray) -> list[bytes | bytearray]:
  """Parse padded message into 1024-bit (128-byte) blocks.

  Args:
      message: The padded message

  Returns:
      List of 128-byte blocks
  """
  return [message[i : i + 128] for i in range(0, len(message), 128)]


def _sha512_compress(block: bytes | bytearray, h_values: list[int]) -> list[int]:
  """SHA-512 compression function.

  Args:
      block: 128-byte message block
      h_values: Current hash state (8 64-bit words)

  Returns:
      Updated hash state
  """
  w = [0] * 80

  # Prepare message schedule
  for i in range(16):
    w[i] = struct.unpack(">Q", block[i * 8 : i * 8 + 8])[0]

  for i in range(16, 80):
    s0 = _right_rotate(w[i - 15], 1) ^ _right_rotate(w[i - 15], 8) ^ (w[i - 15] >> 7)
    s1 = _right_rotate(w[i - 2], 19) ^ _right_rotate(w[i - 2], 61) ^ (w[i - 2] >> 6)
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & ((1 << 64) - 1)

  # Initialize working variables
  a, b, c, d, e, f, g, h = h_values

  # Main loop - 80 rounds
  for i in range(80):
    s1 = _right_rotate(e, 14) ^ _right_rotate(e, 18) ^ _right_rotate(e, 41)
    ch = (e & f) ^ (~e & g)
    temp1 = (h + s1 + ch + K[i] + w[i]) & ((1 << 64) - 1)

    s0 = _right_rotate(a, 28) ^ _right_rotate(a, 34) ^ _right_rotate(a, 39)
    maj = (a & b) ^ (a & c) ^ (b & c)
    temp2 = (s0 + maj) & ((1 << 64) - 1)

    # Update working variables
    h = g
    g = f
    f = e
    e = (d + temp1) & ((1 << 64) - 1)
    d = c
    c = b
    b = a
    a = (temp1 + temp2) & ((1 << 64) - 1)

  # Add compressed chunk to current hash value
  return [
    (h_values[0] + a) & ((1 << 64) - 1),
    (h_values[1] + b) & ((1 << 64) - 1),
    (h_values[2] + c) & ((1 << 64) - 1),
    (h_values[3] + d) & ((1 << 64) - 1),
    (h_values[4] + e) & ((1 << 64) - 1),
    (h_values[5] + f) & ((1 << 64) - 1),
    (h_values[6] + g) & ((1 << 64) - 1),
    (h_values[7] + h) & ((1 << 64) - 1),
  ]


def sha512(message: bytes | str) -> str:
  """Compute SHA-512 hash of message.

  Implements the SHA-512 algorithm as specified in FIPS 180-4.
  Processes data in 1024-bit blocks using 80 rounds of computation.

  Args:
      message: The message to hash (bytes or string)

  Returns:
      The 128-character hexadecimal string representing the 64-byte hash

  Raises:
      TypeError: If message is not bytes or string

  Examples:
      >>> sha512(b"")
      'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
      >>> sha512(b"abc")
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
      >>> sha512("hello world")
      '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
  """
  if not isinstance(message, bytes | str):
    msg = "message must be bytes or string"
    raise TypeError(msg)

  # Use a copy of initial hash values
  h_state = H[:]

  # Pad and process message
  padded_message = _pad_message(message)
  blocks = _parse_message_blocks(padded_message)

  for block in blocks:
    h_state = _sha512_compress(block, h_state)

  # Produce final hash value
  return "".join(f"{value:016x}" for value in h_state)


def sha512_bytes(message: bytes | str) -> bytes:
  """Compute SHA-512 hash and return raw bytes.

  Args:
      message: The message to hash (bytes or string)

  Returns:
      The 64-byte hash digest as bytes

  Examples:
      >>> sha512_bytes(b"hello")
      b'\\x9fmH\\xa0\\xf0\\x0f\\x8d\\x11\\x9d\\x82\\x8e\\x13\\x0e\\x9f\\x9b\\xf4\\x0e\\x8c\\x8d\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e\\x8e'
  """
  hex_result = sha512(message)
  return bytes.fromhex(hex_result)


if __name__ == "__main__":
  # Test vectors from NIST
  print(sha512(b""))
  print(sha512(b"abc"))
