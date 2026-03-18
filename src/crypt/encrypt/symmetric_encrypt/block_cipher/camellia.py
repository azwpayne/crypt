# @author  : azwpayne(https://github.com/azwpayne)
# @name    : camellia.py
# @time    : 2026/3/18
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Camellia block cipher implementation (128-bit block, 128/192/256-bit keys)

"""
Camellia Block Cipher Implementation

Camellia is a 128-bit block cipher designed by NTT and Mitsubishi Electric.
It was selected as a finalist for the AES competition and is widely used
in Japan and TLS cipher suites.

Features:
- 128-bit block size
- Key sizes: 128, 192, 256 bits
- 18 rounds for 128-bit keys
- 24 rounds for 192/256-bit keys
- Feistel network with FL/FL^-1 functions

Reference: RFC 3713, NTT Camellia specification
"""

import struct
from typing import Final

# S-boxes for Camellia (from RFC 3713)
SBOX1: Final[list[int]] = [
  0x70,
  0x82,
  0x2C,
  0xEC,
  0xB3,
  0x27,
  0xC0,
  0xE5,
  0xE4,
  0x85,
  0x57,
  0x35,
  0xEA,
  0x0C,
  0xAE,
  0x41,
  0x23,
  0xEF,
  0x6B,
  0x93,
  0x45,
  0x19,
  0xA5,
  0x21,
  0xED,
  0x0E,
  0x4F,
  0x4E,
  0x1D,
  0x65,
  0x92,
  0xBD,
  0x86,
  0xB8,
  0xAF,
  0x8F,
  0x7C,
  0xEB,
  0x1F,
  0xCE,
  0x3E,
  0x30,
  0xDC,
  0x5F,
  0x5E,
  0xC5,
  0x0B,
  0x1A,
  0xA6,
  0xE1,
  0x39,
  0xCA,
  0xD5,
  0x47,
  0x5D,
  0x3D,
  0xD9,
  0x01,
  0x5A,
  0xD6,
  0x51,
  0x56,
  0x6C,
  0x4D,
  0x8B,
  0x0D,
  0x9A,
  0x66,
  0xFB,
  0xCC,
  0xB0,
  0x2D,
  0x74,
  0x12,
  0x2B,
  0x20,
  0xF0,
  0xB1,
  0x84,
  0x99,
  0xDF,
  0x4C,
  0xCB,
  0xC2,
  0x34,
  0x7E,
  0x76,
  0x05,
  0x6D,
  0xB7,
  0xA9,
  0x31,
  0xD1,
  0x17,
  0x04,
  0xD7,
  0x14,
  0x58,
  0x3A,
  0x61,
  0xDE,
  0x1B,
  0x11,
  0x1C,
  0x32,
  0x0F,
  0x9C,
  0x16,
  0x53,
  0x18,
  0xF2,
  0x22,
  0xFE,
  0x44,
  0xCF,
  0xB2,
  0xC3,
  0xB5,
  0x7A,
  0x91,
  0x24,
  0x08,
  0xE8,
  0xA8,
  0x60,
  0xFC,
  0x69,
  0x50,
  0xAA,
  0xD0,
  0xA0,
  0x7D,
  0xA1,
  0x89,
  0x62,
  0x97,
  0x54,
  0x5B,
  0x1E,
  0x95,
  0xE0,
  0xFF,
  0x64,
  0xD2,
  0x10,
  0xC4,
  0x00,
  0x48,
  0xA3,
  0xF7,
  0x75,
  0xDB,
  0x8A,
  0x03,
  0xE6,
  0xDA,
  0x09,
  0x3F,
  0xDD,
  0x94,
  0x87,
  0x5C,
  0x83,
  0xCD,
  0x90,
  0xD8,
  0xAB,
  0x00,
  0x8C,
  0xA2,
  0x8D,
  0x80,
  0x9F,
  0x68,
  0x71,
  0x96,
  0x33,
  0xF1,
  0xBB,
  0x4B,
  0x0A,
  0x26,
  0xE7,
  0xBA,
  0xF9,
  0x52,
  0x29,
  0xD4,
  0x7B,
  0x9D,
  0x98,
  0x78,
  0xC6,
  0x9E,
  0x9B,
  0x06,
  0xF8,
  0x2E,
  0x36,
  0x4A,
  0x79,
  0x3B,
  0x81,
  0x9B,
  0x3C,
  0x42,
  0xC7,
  0x63,
  0x2F,
  0x88,
  0x2A,
  0xF5,
  0x73,
  0x59,
  0x77,
  0x25,
  0xF4,
  0x46,
  0xC8,
  0xBE,
  0x6A,
  0x49,
  0x6F,
  0x37,
  0xE3,
  0xC1,
  0xAD,
  0x67,
  0x2A,
  0x43,
  0x55,
  0xF6,
  0x38,
  0x13,
  0xE2,
  0x72,
  0x7F,
  0x2B,
  0x40,
  0x6E,
  0xBC,
  0x28,
  0xA4,
  0xBF,
  0x15,
  0xEE,
  0xAC,
  0xA7,
  0xF3,
  0x3B,
  0x8E,
  0x07,
  0xFA,
  0x4B,
  0x2A,
  0x90,
]

# SBOX2[i] = SBOX1[i] <<< 1 (rotate left by 1 bit)
SBOX2: Final[list[int]] = [(x << 1 | x >> 7) & 0xFF for x in SBOX1]

# SBOX3[i] = SBOX1[i] <<< 7 (rotate left by 7 bits)
SBOX3: Final[list[int]] = [(x << 7 | x >> 1) & 0xFF for x in SBOX1]

# SBOX4[i] = SBOX1[i <<< 1] - SBOX1 indexed by (i rotated left by 1)
SBOX4: Final[list[int]] = [SBOX1[(i << 1 | i >> 7) & 0xFF] for i in range(256)]

# Sigma constants for key schedule (hex digits of pi)
SIGMA: Final[list[int]] = [
  0xA09E667F3BCC908B,
  0xB67AE8584CAA73B2,
  0xC6EF372FE94F82BE,
  0x54FF53A5F1D36F1C,
  0x10E527FADE682D1D,
  0xB05688C2B3E6C1FD,
]


def _bytes_to_dword(data: bytes) -> int:
  """Convert 8 bytes to a 64-bit word (big-endian)."""
  return struct.unpack(">Q", data)[0]


def _dword_to_bytes(dword: int) -> bytes:
  """Convert a 64-bit word to 8 bytes (big-endian)."""
  return struct.pack(">Q", dword & 0xFFFFFFFFFFFFFFFF)


def _rol(x: int, n: int) -> int:
  """Rotate left a 64-bit value by n bits."""
  n = n % 64
  return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _ror(x: int, n: int) -> int:
  """Rotate right a 64-bit value by n bits."""
  n = n % 64
  return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _rol32(x: int, n: int) -> int:
  """Rotate left a 32-bit value by n bits."""
  n = n % 32
  return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f_function(x: int, k: int) -> int:
  """Camellia F-function.

  Args:
      x: 64-bit input
      k: 64-bit round key

  Returns:
      64-bit output
  """
  # XOR with round key
  y = x ^ k

  # Split into bytes and apply S-boxes
  y1 = (y >> 56) & 0xFF
  y2 = (y >> 48) & 0xFF
  y3 = (y >> 40) & 0xFF
  y4 = (y >> 32) & 0xFF
  y5 = (y >> 24) & 0xFF
  y6 = (y >> 16) & 0xFF
  y7 = (y >> 8) & 0xFF
  y8 = y & 0xFF

  # Apply S-boxes according to RFC 3713
  z1 = SBOX1[y1]
  z2 = SBOX2[y2]
  z3 = SBOX3[y3]
  z4 = SBOX4[y4]
  z5 = SBOX2[y5]
  z6 = SBOX3[y6]
  z7 = SBOX4[y7]
  z8 = SBOX1[y8]

  # P-function (diffusion layer) - from RFC 3713
  h1 = z1 ^ z3 ^ z4 ^ z6 ^ z7 ^ z8
  h2 = z1 ^ z2 ^ z4 ^ z5 ^ z7 ^ z8
  h3 = z1 ^ z2 ^ z3 ^ z5 ^ z6 ^ z8
  h4 = z2 ^ z3 ^ z4 ^ z5 ^ z6 ^ z7
  h5 = z1 ^ z2 ^ z6 ^ z7 ^ z8
  h6 = z2 ^ z3 ^ z5 ^ z7 ^ z8
  h7 = z3 ^ z4 ^ z5 ^ z6 ^ z8
  h8 = z1 ^ z4 ^ z5 ^ z6 ^ z7

  # Combine into 64-bit output
  return (
    (h1 << 56)
    | (h2 << 48)
    | (h3 << 40)
    | (h4 << 32)
    | (h5 << 24)
    | (h6 << 16)
    | (h7 << 8)
    | h8
  )


def _fl_function(x: int, k: int) -> int:
  """Camellia FL-function (used every 6 rounds).

  Args:
      x: 64-bit input
      k: 64-bit key

  Returns:
      64-bit output
  """
  xl = (x >> 32) & 0xFFFFFFFF
  xr = x & 0xFFFFFFFF
  kl = (k >> 32) & 0xFFFFFFFF
  kr = k & 0xFFFFFFFF

  # FL operation from RFC 3713
  # XL' = XL ^ ROL(XR & KRL, 1)
  # XR' = XR ^ (XL' | KRR)
  xl_new = xl ^ _rol32(xr & kl, 1)
  xr_new = xr ^ (xl_new | kr)

  return (xl_new << 32) | xr_new


def _fl_inv_function(y: int, k: int) -> int:
  """Camellia FL^-1 function (inverse of FL).

  Args:
      y: 64-bit input
      k: 64-bit key

  Returns:
      64-bit output
  """
  yl = (y >> 32) & 0xFFFFFFFF
  yr = y & 0xFFFFFFFF
  kl = (k >> 32) & 0xFFFFFFFF
  kr = k & 0xFFFFFFFF

  # FL^-1 operation from RFC 3713
  # YR = YR ^ (YL | KRR)
  # YL = YL ^ ROL(YR & KRL, 1)
  yr_new = yr ^ (yl | kr)
  yl_new = yl ^ _rol32(yr_new & kl, 1)

  return (yl_new << 32) | yr_new


class Camellia:
  """Camellia block cipher implementation.

  Camellia is a 128-bit block cipher supporting 128/192/256-bit keys.
  It uses a Feistel network with 18 rounds (for 128-bit keys) or
  24 rounds (for 192/256-bit keys).

  Attributes:
      key_size: Size of the key in bits (128, 192, or 256)
      rounds: Number of rounds (18 or 24)
      kw: Whitening keys (4 x 64-bit)
      k: Round keys (24 x 64-bit)
      kl: FL keys (6 x 64-bit)
  """

  def __init__(self, key: bytes) -> None:
    """Initialize Camellia with a key.

    Args:
        key: The encryption key (16, 24, or 32 bytes)

    Raises:
        ValueError: If key length is invalid
    """
    key_len = len(key)
    if key_len == 16:
      self.key_size = 128
      self.rounds = 18
    elif key_len == 24:
      self.key_size = 192
      self.rounds = 24
    elif key_len == 32:
      self.key_size = 256
      self.rounds = 24
    else:
      msg = f"Invalid key length: {key_len}. Must be 16, 24, or 32 bytes."
      raise ValueError(msg)

    # Initialize key arrays
    self.kw: list[int] = [0] * 4  # Whitening keys
    self.k: list[int] = [0] * 24  # Round keys
    self.kl: list[int] = [0] * 6  # FL keys

    self._key_schedule(key)

  def _key_schedule(self, key: bytes) -> None:
    """Generate round keys from the master key."""
    # Pad 192-bit key to 256-bit
    if len(key) == 24:
      key = key + b"\x00" * 8

    # Split key into two 128-bit halves
    kla = _bytes_to_dword(key[:8])
    klb = _bytes_to_dword(key[8:16])

    if self.key_size == 128:
      kla2, klb2 = 0, 0
    else:
      kla2 = _bytes_to_dword(key[16:24])
      klb2 = _bytes_to_dword(key[24:32])

    # KL and KR
    kl = [kla, klb]
    kr = [kla2, klb2]

    # Generate KA using Feistel rounds with sigma constants
    d1 = kl[0] ^ kr[0]
    d2 = kl[1] ^ kr[1]

    d2 ^= _f_function(d1, SIGMA[0])
    d1 ^= _f_function(d2, SIGMA[1])
    d1 ^= kl[0]  # XOR with KL high 64 bits
    d2 ^= kl[1]  # XOR with KL low 64 bits
    d2 ^= _f_function(d1, SIGMA[2])
    d1 ^= _f_function(d2, SIGMA[3])

    ka = [d1, d2]

    if self.key_size == 128:
      kb = [0, 0]
    else:
      # Generate KB for 192/256-bit keys
      d1 = ka[0] ^ kr[0]
      d2 = ka[1] ^ kr[1]
      d2 ^= _f_function(d1, SIGMA[4])
      d1 ^= _f_function(d2, SIGMA[5])
      kb = [d1, d2]

    # Generate subkeys
    if self.key_size == 128:
      self._generate_subkeys_128(kl, ka)
    else:
      self._generate_subkeys_192_256(kl, kr, ka, kb)

  def _generate_subkeys_128(self, kl: list[int], ka: list[int]) -> None:  # noqa: PLR0915
    """Generate subkeys for 128-bit key per RFC 3713."""

    # Helper function to rotate 128-bit value and extract high/low parts
    def rol128(high: int, low: int, n: int) -> tuple[int, int]:
      """Rotate 128-bit value (high<<64)|low left by n bits, return (new_high, new_low)."""
      n = n % 128
      if n < 64:
        # Bits rotate from low to high
        new_high = ((high << n) | (low >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
        new_low = ((low << n) | (high >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
      elif n == 64:
        new_high = low
        new_low = high
      else:  # n > 64
        n = n - 64
        new_high = ((low << n) | (high >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
        new_low = ((high << n) | (low >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
      return new_high, new_low

    # KL = (kl[0] << 64) | kl[1]
    # KA = (ka[0] << 64) | ka[1]

    # Whitening keys
    self.kw[0] = kl[0]  # (KL <<< 0) >> 64
    self.kw[1] = kl[1]  # (KL <<< 0) & MASK64

    # kw3, kw4 from KA <<< 111
    ka_111_h, ka_111_l = rol128(ka[0], ka[1], 111)
    self.kw[2] = ka_111_h
    self.kw[3] = ka_111_l

    # Round keys - derived from rotated KL and KA
    # k1, k2 from KA <<< 0
    self.k[0] = ka[0]
    self.k[1] = ka[1]

    # k3, k4 from KL <<< 15
    kl_15_h, kl_15_l = rol128(kl[0], kl[1], 15)
    self.k[2] = kl_15_h
    self.k[3] = kl_15_l

    # k5, k6 from KA <<< 15
    ka_15_h, ka_15_l = rol128(ka[0], ka[1], 15)
    self.k[4] = ka_15_h
    self.k[5] = ka_15_l

    # k7, k8 from KL <<< 45
    kl_45_h, kl_45_l = rol128(kl[0], kl[1], 45)
    self.k[6] = kl_45_h
    self.k[7] = kl_45_l

    # k9, k10 from KA <<< 45
    ka_45_h, ka_45_l = rol128(ka[0], ka[1], 45)
    self.k[8] = ka_45_h
    self.k[9] = ka_45_l

    # k11, k12 from KA <<< 60
    ka_60_h, ka_60_l = rol128(ka[0], ka[1], 60)
    self.k[10] = ka_60_h
    self.k[11] = ka_60_l

    # k13, k14 from KL <<< 94
    kl_94_h, kl_94_l = rol128(kl[0], kl[1], 94)
    self.k[12] = kl_94_h
    self.k[13] = kl_94_l

    # k15, k16 from KA <<< 94
    ka_94_h, ka_94_l = rol128(ka[0], ka[1], 94)
    self.k[14] = ka_94_h
    self.k[15] = ka_94_l

    # k17, k18 from KL <<< 111
    kl_111_h, kl_111_l = rol128(kl[0], kl[1], 111)
    self.k[16] = kl_111_h
    self.k[17] = kl_111_l

    # FL keys (ke1..ke4 in RFC 3713)
    # ke1, ke2 from KA <<< 30
    ka_30_h, ka_30_l = rol128(ka[0], ka[1], 30)
    self.kl[0] = ka_30_h
    self.kl[1] = ka_30_l

    # ke3, ke4 from KL <<< 77
    kl_77_h, kl_77_l = rol128(kl[0], kl[1], 77)
    self.kl[2] = kl_77_h
    self.kl[3] = kl_77_l

    # Note: kl[4] and kl[5] are not used for 128-bit keys

  def _generate_subkeys_192_256(
    self, kl: list[int], kr: list[int], ka: list[int], kb: list[int]
  ) -> None:
    """Generate subkeys for 192/256-bit key."""
    # Whitening keys
    self.kw[0] = kl[0]
    self.kw[1] = kl[1]
    self.kw[2] = kb[0]
    self.kw[3] = kb[1]

    # Round keys
    self.k[0] = kr[0]
    self.k[1] = kr[1]
    self.k[2] = _rol(ka[0], 15)
    self.k[3] = _rol(ka[1], 15)
    self.k[4] = _rol(kb[0], 15)
    self.k[5] = _rol(kb[1], 15)
    self.k[6] = kr[0]
    self.k[7] = kr[1]
    self.k[8] = _rol(ka[0], 30)
    self.k[9] = _rol(ka[1], 30)
    self.k[10] = kl[0]
    self.k[11] = kl[1]
    self.k[12] = _rol(ka[0], 47)
    self.k[13] = _rol(ka[1], 47)
    self.k[14] = _rol(kl[0], 47)
    self.k[15] = _rol(kl[1], 47)
    self.k[16] = _rol(kb[0], 60)
    self.k[17] = _rol(kb[1], 60)
    self.k[18] = _rol(kr[0], 60)
    self.k[19] = _rol(kr[1], 60)
    self.k[20] = _rol(ka[0], 77)
    self.k[21] = _rol(ka[1], 77)
    self.k[22] = _rol(kl[0], 94)
    self.k[23] = _rol(kl[1], 94)

    # FL keys
    self.kl[0] = _rol(kr[0], 30)
    self.kl[1] = _rol(kr[1], 30)
    self.kl[2] = kb[0]
    self.kl[3] = kb[1]
    self.kl[4] = _rol(ka[0], 30)
    self.kl[5] = _rol(ka[1], 30)

  def encrypt_block(self, block: bytes) -> bytes:
    """Encrypt a single 128-bit block.

    Args:
        block: 16-byte block to encrypt

    Returns:
        16-byte encrypted block
    """
    if len(block) != 16:
      msg = f"Block must be 16 bytes, got {len(block)}"
      raise ValueError(msg)

    # Split into left and right halves
    d1 = _bytes_to_dword(block[:8])
    d2 = _bytes_to_dword(block[8:])

    # Pre-whitening
    d1 ^= self.kw[0]
    d2 ^= self.kw[1]

    # Feistel rounds
    if self.key_size == 128:
      # 18 rounds for 128-bit key
      # Rounds 1-6
      for i in range(6):
        d2 ^= _f_function(d1, self.k[i])
        d1, d2 = d2, d1

      # FL layer after round 6 (before round 7)
      d1 = _fl_function(d1, self.kl[0])
      d2 = _fl_inv_function(d2, self.kl[1])

      # Rounds 7-12
      for i in range(6, 12):
        d2 ^= _f_function(d1, self.k[i])
        d1, d2 = d2, d1

      # FL layer after round 12 (before round 13)
      d1 = _fl_function(d1, self.kl[2])
      d2 = _fl_inv_function(d2, self.kl[3])

      # Rounds 13-18
      for i in range(12, 18):
        d2 ^= _f_function(d1, self.k[i])
        d1, d2 = d2, d1
    else:
      # 24 rounds for 192/256-bit keys
      # Rounds 1-6
      for i in range(6):
        d2 ^= _f_function(d1, self.k[i])
        d1, d2 = d2, d1

      # FL layer after round 6 (before round 7)
      d1 = _fl_function(d1, self.kl[0])
      d2 = _fl_inv_function(d2, self.kl[1])

      # Rounds 7-12
      for i in range(6, 12):
        d2 ^= _f_function(d1, self.k[i])
        d1, d2 = d2, d1

      # FL layer after round 12 (before round 13)
      d1 = _fl_function(d1, self.kl[2])
      d2 = _fl_inv_function(d2, self.kl[3])

      # Rounds 13-18
      for i in range(12, 18):
        d2 ^= _f_function(d1, self.k[i])
        d1, d2 = d2, d1

      # FL layer after round 18 (before round 19)
      d1 = _fl_function(d1, self.kl[4])
      d2 = _fl_inv_function(d2, self.kl[5])

      # Rounds 19-24
      for i in range(18, 24):
        d2 ^= _f_function(d1, self.k[i])
        d1, d2 = d2, d1

    # Post-whitening (swap and apply)
    d2 ^= self.kw[2]
    d1 ^= self.kw[3]

    return _dword_to_bytes(d2) + _dword_to_bytes(d1)

  def decrypt_block(self, block: bytes) -> bytes:
    """Decrypt a single 128-bit block.

    Args:
        block: 16-byte block to decrypt

    Returns:
        16-byte decrypted block
    """
    if len(block) != 16:
      msg = f"Block must be 16 bytes, got {len(block)}"
      raise ValueError(msg)

    # Split into left and right halves
    d1 = _bytes_to_dword(block[:8])
    d2 = _bytes_to_dword(block[8:])

    # Reverse post-whitening
    # Ciphertext is: bytes(d2_after_whitening) + bytes(d1_after_whitening)
    # So d1 = d2_enc ^ kw[2] and d2 = d1_enc ^ kw[3]
    # To reverse: d1 ^= kw[2] gives d2_enc, d2 ^= kw[3] gives d1_enc
    d1 ^= self.kw[2]
    d2 ^= self.kw[3]

    # Swap to match encryption state after round 18
    d1, d2 = d2, d1

    # Reverse Feistel rounds
    if self.key_size == 128:
      # Reverse rounds 18-13 (k[17] to k[12])
      for i in range(17, 11, -1):
        d1, d2 = d2, d1
        d2 ^= _f_function(d1, self.k[i])

      # Reverse FL layer after round 12 (before round 13)
      d1 = _fl_inv_function(d1, self.kl[2])
      d2 = _fl_function(d2, self.kl[3])

      # Reverse rounds 12-7 (k[11] to k[6])
      for i in range(11, 5, -1):
        d1, d2 = d2, d1
        d2 ^= _f_function(d1, self.k[i])

      # Reverse FL layer after round 6 (before round 7)
      d1 = _fl_inv_function(d1, self.kl[0])
      d2 = _fl_function(d2, self.kl[1])

      # Reverse rounds 6-1 (k[5] to k[0])
      for i in range(5, -1, -1):
        d1, d2 = d2, d1
        d2 ^= _f_function(d1, self.k[i])
    else:
      # 24 rounds for 192/256-bit keys
      # Reverse rounds 24-19 (k[23] to k[18])
      for i in range(23, 17, -1):
        d1, d2 = d2, d1
        d2 ^= _f_function(d1, self.k[i])

      # Reverse FL layer after round 18 (before round 19)
      d1 = _fl_inv_function(d1, self.kl[4])
      d2 = _fl_function(d2, self.kl[5])

      # Reverse rounds 18-13 (k[17] to k[12])
      for i in range(17, 11, -1):
        d1, d2 = d2, d1
        d2 ^= _f_function(d1, self.k[i])

      # Reverse FL layer after round 12 (before round 13)
      d1 = _fl_inv_function(d1, self.kl[2])
      d2 = _fl_function(d2, self.kl[3])

      # Reverse rounds 12-7 (k[11] to k[6])
      for i in range(11, 5, -1):
        d1, d2 = d2, d1
        d2 ^= _f_function(d1, self.k[i])

      # Reverse FL layer after round 6 (before round 7)
      d1 = _fl_inv_function(d1, self.kl[0])
      d2 = _fl_function(d2, self.kl[1])

      # Reverse rounds 6-1 (k[5] to k[0])
      for i in range(5, -1, -1):
        d1, d2 = d2, d1
        d2 ^= _f_function(d1, self.k[i])

    # Reverse pre-whitening
    d1 ^= self.kw[0]
    d2 ^= self.kw[1]

    return _dword_to_bytes(d1) + _dword_to_bytes(d2)


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
  """Encrypt data using Camellia in ECB mode.

  Args:
      key: Encryption key (16, 24, or 32 bytes)
      plaintext: Data to encrypt (will be padded to 16-byte boundary)

  Returns:
      Encrypted data
  """
  cipher = Camellia(key)

  # PKCS7 padding
  pad_len = 16 - (len(plaintext) % 16)
  if pad_len == 0:
    pad_len = 16
  padded = plaintext + bytes([pad_len] * pad_len)

  ciphertext = bytearray()
  for i in range(0, len(padded), 16):
    block = padded[i : i + 16]
    ciphertext.extend(cipher.encrypt_block(block))

  return bytes(ciphertext)


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
  """Decrypt data using Camellia in ECB mode.

  Args:
      key: Encryption key (16, 24, or 32 bytes)
      ciphertext: Data to decrypt (must be multiple of 16 bytes)

  Returns:
      Decrypted data with padding removed
  """
  if len(ciphertext) % 16 != 0:
    msg = "Ciphertext length must be a multiple of 16"
    raise ValueError(msg)

  cipher = Camellia(key)

  plaintext = bytearray()
  for i in range(0, len(ciphertext), 16):
    block = ciphertext[i : i + 16]
    plaintext.extend(cipher.decrypt_block(block))

  # Remove PKCS7 padding
  pad_len = plaintext[-1]
  if pad_len > 16:
    msg = "Invalid padding"
    raise ValueError(msg)
  return bytes(plaintext[:-pad_len])


def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
  """Encrypt data using Camellia in CBC mode.

  Args:
      key: Encryption key (16, 24, or 32 bytes)
      iv: Initialization vector (16 bytes)
      plaintext: Data to encrypt

  Returns:
      Encrypted data
  """
  if len(iv) != 16:
    msg = f"IV must be 16 bytes, got {len(iv)}"
    raise ValueError(msg)

  cipher = Camellia(key)

  # PKCS7 padding
  pad_len = 16 - (len(plaintext) % 16)
  if pad_len == 0:
    pad_len = 16
  padded = plaintext + bytes([pad_len] * pad_len)

  ciphertext = bytearray()
  prev_block = iv

  for i in range(0, len(padded), 16):
    block = padded[i : i + 16]
    # XOR with previous ciphertext block (or IV)
    xored = bytes(a ^ b for a, b in zip(block, prev_block, strict=True))
    encrypted = cipher.encrypt_block(xored)
    ciphertext.extend(encrypted)
    prev_block = encrypted

  return bytes(ciphertext)


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
  """Decrypt data using Camellia in CBC mode.

  Args:
      key: Encryption key (16, 24, or 32 bytes)
      iv: Initialization vector (16 bytes)
      ciphertext: Data to decrypt (must be multiple of 16 bytes)

  Returns:
      Decrypted data with padding removed
  """
  if len(ciphertext) % 16 != 0:
    msg = "Ciphertext length must be a multiple of 16"
    raise ValueError(msg)
  if len(iv) != 16:
    msg = f"IV must be 16 bytes, got {len(iv)}"
    raise ValueError(msg)

  cipher = Camellia(key)

  plaintext = bytearray()
  prev_block = iv

  for i in range(0, len(ciphertext), 16):
    block = ciphertext[i : i + 16]
    decrypted = cipher.decrypt_block(block)
    # XOR with previous ciphertext block (or IV)
    xored = bytes(a ^ b for a, b in zip(decrypted, prev_block, strict=True))
    plaintext.extend(xored)
    prev_block = block

  # Remove PKCS7 padding
  pad_len = plaintext[-1]
  if pad_len > 16:
    msg = "Invalid padding"
    raise ValueError(msg)
  return bytes(plaintext[:-pad_len])
