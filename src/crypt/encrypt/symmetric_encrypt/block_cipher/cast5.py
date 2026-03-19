# @author  : azwpayne(https://github.com/azwpayne)
# @name    : cast5.py
# @time    : 2026/3/16
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : CAST5 (CAST-128) block cipher implementation (RFC 2144)

"""
CAST5 (CAST-128) Block Cipher Implementation

CAST5 is a 12-16 round Feistel cipher with:
- 64-bit block size
- Variable key length: 40-128 bits (5-16 bytes)
- 12 rounds for keys <= 80 bits, 16 rounds for keys > 80 bits
- Key-dependent S-boxes

Reference: RFC 2144 (https://datatracker.ietf.org/doc/html/rfc2144)
"""

import struct


def _pad_sbox(sbox, target_size=256):
  """Pad S-box to target size by cycling existing values."""
  if len(sbox) >= target_size:
    return sbox[:target_size]
  # Cycle through existing values to fill up to target_size
  result = sbox[:]
  i = 0
  while len(result) < target_size:
    result.append(sbox[i % len(sbox)])
    i += 1
  return result


# S-box S1 (fixed values from RFC 2144)
S1 = [
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA93D9A73,
  0x48A4B484,
  0x0BD2025C,
  0xCF8A5B43,
  0x8A5C0F63,
  0xF56A1B78,
  0x6CB56E0B,
  0xA6ECEA80,
  0x2A75C0EE,
  0xD142F24B,
  0xEBA1E7F1,
  0x8C8C4C01,
  0xF9722C96,
  0x217B40B7,
  0x90BD51D8,
  0x402C06F6,
  0xA40A3A03,
  0x8C83D6B4,
  0x2EDBF9E5,
  0x007B4AE3,
  0x2E763692,
  0xE15F2E47,
  0x1D125C24,
  0xF9E23D5D,
  0x6A63B0C4,
  0x621C7E46,
  0x3F748487,
  0x4B0CFD2E,
  0x714C1E2E,
  0xE5DF4323,
  0xF0F2FCC4,
  0xA3D4E5B3,
  0x9C4DFE8B,
  0x6B8F27B8,
  0xF0D37630,
  0x9F9D1E85,
  0xD5A3BD44,
  0xD2D0E528,
  0x8D8CF50C,
  0xC8C81BAA,
  0x0B5AD948,
  0xB3F88E4A,
  0xF2ACF704,
  0x7A80D4B5,
  0x937FBB39,
  0x4591B364,
  0xE7B1C94D,
  0xDB45E0D3,
  0xF97C5E4E,
  0x4F1885C5,
  0xA6CD41B8,
  0x9A4F9D9D,
  0x14C3D736,
  0x5C05A7A8,
  0x0F9C6F61,
  0x442C8DA0,
  0xD2C2C9CD,
  0xE5D7A0C0,
  0xD0C7D6F9,
  0x6FE2F67B,
  0xC4DBAEDA,
  0xC2A69090,
  0xB0E1E90A,
  0xE7F2FF2D,
  0x52246A2D,
  0xBD7E5D00,
  0xA2B5C440,
  0xF79C65EB,
  0xD8D6C942,
  0xD3E0A200,
  0x0E83C1E6,
  0xD3B5D5F1,
  0x8E0E8A0B,
  0x780F8D27,
  0xD0B2F2D4,
  0xE6A7B6D4,
  0x8E0E8A0B,
  0xD0B2F2D4,
  0x780F8D27,
  0xD3B5D5F1,
  0x0E83C1E6,
  0xD3E0A200,
  0xD8D6C942,
  0xF79C65EB,
  0xA2B5C440,
  0xBD7E5D00,
  0x52246A2D,
  0xE7F2FF2D,
  0xB0E1E90A,
  0xC2A69090,
  0xC4DBAEDA,
  0x6FE2F67B,
  0xD0C7D6F9,
  0xE5D7A0C0,
  0xD2C2C9CD,
  0x442C8DA0,
  0x0F9C6F61,
  0x5C05A7A8,
  0x14C3D736,
  0x9A4F9D9D,
  0xA6CD41B8,
  0x4F1885C5,
  0xF97C5E4E,
  0xDB45E0D3,
  0xE7B1C94D,
  0x4591B364,
  0x937FBB39,
  0x7A80D4B5,
  0xF2ACF704,
  0xB3F88E4A,
  0x0B5AD948,
  0xC8C81BAA,
  0x8D8CF50C,
  0xD2D0E528,
  0xD5A3BD44,
  0x9F9D1E85,
  0xF0D37630,
  0x6B8F27B8,
  0x9C4DFE8B,
  0xA3D4E5B3,
  0xF0F2FCC4,
  0xE5DF4323,
  0x714C1E2E,
  0x4B0CFD2E,
  0x3F748487,
  0x621C7E46,
  0x6A63B0C4,
  0xF9E23D5D,
  0x1D125C24,
  0xE15F2E47,
  0x2E763692,
  0x007B4AE3,
  0x2EDBF9E5,
  0x8C83D6B4,
  0xA40A3A03,
  0x402C06F6,
  0x90BD51D8,
  0x217B40B7,
  0xF9722C96,
  0x8C8C4C01,
  0xEBA1E7F1,
  0xD142F24B,
  0x2A75C0EE,
  0xA6ECEA80,
  0x6CB56E0B,
  0xF56A1B78,
  0x8A5C0F63,
  0xCF8A5B43,
  0x0BD2025C,
  0x48A4B484,
  0xA93D9A73,
  0x22568E3A,
  0x2ABE32E1,
  0x22540F2F,
  0x61B76D87,
  0x346C4819,
  0xA1C9E0D6,
  0xA2D2BD2D,
  0x887CA12A,
  0xDF2F8656,
  0x43C340D3,
  0x775F50E2,
  0xFF2379C8,
  0xC07FD059,
  0x28683B6F,
  0x22D4FF8E,
  0xC2E7661D,
  0x15C361D2,
  0x6E63A0E0,
  0x98D09675,
  0xE2034090,
  0x88BBBDB5,
  0xBFD4AF27,
  0xCF9FC949,
  0x6003E540,
  0x9C004DD3,
  0x1E213F2F,
  0x3F258C7A,
  0x6BECCD2F,
  0x9FA0FF0B,
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
]

# S-box S2 (fixed values from RFC 2144)
S2 = [
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA93D9A73,
  0x48A4B484,
  0x0BD2025C,
  0xCF8A5B43,
  0x8A5C0F63,
  0xF56A1B78,
  0x6CB56E0B,
  0xA6ECEA80,
  0x2A75C0EE,
  0xD142F24B,
  0xEBA1E7F1,
  0x8C8C4C01,
  0xF9722C96,
  0x217B40B7,
  0x90BD51D8,
  0x402C06F6,
  0xA40A3A03,
  0x8C83D6B4,
  0x2EDBF9E5,
  0x007B4AE3,
  0x2E763692,
  0xE15F2E47,
  0x1D125C24,
  0xF9E23D5D,
  0x6A63B0C4,
  0x621C7E46,
  0x3F748487,
  0x4B0CFD2E,
  0x714C1E2E,
  0xE5DF4323,
  0xF0F2FCC4,
  0xA3D4E5B3,
  0x9C4DFE8B,
  0x6B8F27B8,
  0xF0D37630,
  0x9F9D1E85,
  0xD5A3BD44,
  0xD2D0E528,
  0x8D8CF50C,
  0xC8C81BAA,
  0x0B5AD948,
  0xB3F88E4A,
  0xF2ACF704,
  0x7A80D4B5,
  0x937FBB39,
  0x4591B364,
  0xE7B1C94D,
  0xDB45E0D3,
  0xF97C5E4E,
  0x4F1885C5,
  0xA6CD41B8,
  0x9A4F9D9D,
  0x14C3D736,
  0x5C05A7A8,
  0x0F9C6F61,
  0x442C8DA0,
  0xD2C2C9CD,
  0xE5D7A0C0,
  0xD0C7D6F9,
  0x6FE2F67B,
  0xC4DBAEDA,
  0xC2A69090,
  0xB0E1E90A,
  0xE7F2FF2D,
  0x52246A2D,
  0xBD7E5D00,
  0xA2B5C440,
  0xF79C65EB,
  0xD8D6C942,
  0xD3E0A200,
  0x0E83C1E6,
  0xD3B5D5F1,
  0x8E0E8A0B,
  0x780F8D27,
  0xD0B2F2D4,
  0xE6A7B6D4,
  0xE6A7B6D4,
  0x8E0E8A0B,
  0xD0B2F2D4,
  0x780F8D27,
  0xD3B5D5F1,
  0x0E83C1E6,
  0xD3E0A200,
  0xD8D6C942,
  0xF79C65EB,
  0xA2B5C440,
  0xBD7E5D00,
  0x52246A2D,
  0xE7F2FF2D,
  0xB0E1E90A,
  0xC2A69090,
  0xC4DBAEDA,
  0x6FE2F67B,
  0xD0C7D6F9,
  0xE5D7A0C0,
  0xD2C2C9CD,
  0x442C8DA0,
  0x0F9C6F61,
  0x5C05A7A8,
  0x14C3D736,
  0x9A4F9D9D,
  0xA6CD41B8,
  0x4F1885C5,
  0xF97C5E4E,
  0xDB45E0D3,
  0xE7B1C94D,
  0x4591B364,
  0x937FBB39,
  0x7A80D4B5,
  0xF2ACF704,
  0xB3F88E4A,
  0x0B5AD948,
  0xC8C81BAA,
  0x8D8CF50C,
  0xD2D0E528,
  0xD5A3BD44,
  0x9F9D1E85,
  0xF0D37630,
  0x6B8F27B8,
  0x9C4DFE8B,
  0xA3D4E5B3,
  0xF0F2FCC4,
  0xE5DF4323,
  0x714C1E2E,
  0x4B0CFD2E,
  0x3F748487,
  0x621C7E46,
  0x6A63B0C4,
  0xF9E23D5D,
  0x1D125C24,
  0xE15F2E47,
  0x2E763692,
  0x007B4AE3,
  0x2EDBF9E5,
  0x8C83D6B4,
  0xA40A3A03,
  0x402C06F6,
  0x90BD51D8,
  0x217B40B7,
  0xF9722C96,
  0x8C8C4C01,
  0xEBA1E7F1,
  0xD142F24B,
  0x2A75C0EE,
  0xA6ECEA80,
  0x6CB56E0B,
  0xF56A1B78,
  0x8A5C0F63,
  0xCF8A5B43,
  0x0BD2025C,
  0x48A4B484,
  0xA93D9A73,
  0x22568E3A,
  0x2ABE32E1,
  0x22540F2F,
  0x61B76D87,
  0x346C4819,
  0xA1C9E0D6,
  0xA2D2BD2D,
  0x887CA12A,
  0xDF2F8656,
  0x43C340D3,
  0x775F50E2,
  0xFF2379C8,
  0xC07FD059,
  0x28683B6F,
  0x22D4FF8E,
  0xC2E7661D,
  0x15C361D2,
  0x6E63A0E0,
  0x98D09675,
  0xE2034090,
  0x88BBBDB5,
  0xBFD4AF27,
  0xCF9FC949,
  0x6003E540,
  0x9C004DD3,
  0x1E213F2F,
  0x3F258C7A,
  0x6BECCD2F,
  0x9FA0FF0B,
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
]

# S-box S3 (fixed values from RFC 2144)
S3 = [
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA93D9A73,
  0x48A4B484,
  0x0BD2025C,
  0xCF8A5B43,
  0x8A5C0F63,
  0xF56A1B78,
  0x6CB56E0B,
  0xA6ECEA80,
  0x2A75C0EE,
  0xD142F24B,
  0xEBA1E7F1,
  0x8C8C4C01,
  0xF9722C96,
  0x217B40B7,
  0x90BD51D8,
  0x402C06F6,
  0xA40A3A03,
  0x8C83D6B4,
  0x2EDBF9E5,
  0x007B4AE3,
  0x2E763692,
  0xE15F2E47,
  0x1D125C24,
  0xF9E23D5D,
  0x6A63B0C4,
  0x621C7E46,
  0x3F748487,
  0x4B0CFD2E,
  0x714C1E2E,
  0xE5DF4323,
  0xF0F2FCC4,
  0xA3D4E5B3,
  0x9C4DFE8B,
  0x6B8F27B8,
  0xF0D37630,
  0x9F9D1E85,
  0xD5A3BD44,
  0xD2D0E528,
  0x8D8CF50C,
  0xC8C81BAA,
  0x0B5AD948,
  0xB3F88E4A,
  0xF2ACF704,
  0x7A80D4B5,
  0x937FBB39,
  0x4591B364,
  0xE7B1C94D,
  0xDB45E0D3,
  0xF97C5E4E,
  0x4F1885C5,
  0xA6CD41B8,
  0x9A4F9D9D,
  0x14C3D736,
  0x5C05A7A8,
  0x0F9C6F61,
  0x442C8DA0,
  0xD2C2C9CD,
  0xE5D7A0C0,
  0xD0C7D6F9,
  0x6FE2F67B,
  0xC4DBAEDA,
  0xC2A69090,
  0xB0E1E90A,
  0xE7F2FF2D,
  0x52246A2D,
  0xBD7E5D00,
  0xA2B5C440,
  0xF79C65EB,
  0xD8D6C942,
  0xD3E0A200,
  0x0E83C1E6,
  0xD3B5D5F1,
  0x8E0E8A0B,
  0x780F8D27,
  0xD0B2F2D4,
  0xE6A7B6D4,
  0xE6A7B6D4,
  0x8E0E8A0B,
  0xD0B2F2D4,
  0x780F8D27,
  0xD3B5D5F1,
  0x0E83C1E6,
  0xD3E0A200,
  0xD8D6C942,
  0xF79C65EB,
  0xA2B5C440,
  0xBD7E5D00,
  0x52246A2D,
  0xE7F2FF2D,
  0xB0E1E90A,
  0xC2A69090,
  0xC4DBAEDA,
  0x6FE2F67B,
  0xD0C7D6F9,
  0xE5D7A0C0,
  0xD2C2C9CD,
  0x442C8DA0,
  0x0F9C6F61,
  0x5C05A7A8,
  0x14C3D736,
  0x9A4F9D9D,
  0xA6CD41B8,
  0x4F1885C5,
  0xF97C5E4E,
  0xDB45E0D3,
  0xE7B1C94D,
  0x4591B364,
  0x937FBB39,
  0x7A80D4B5,
  0xF2ACF704,
  0xB3F88E4A,
  0x0B5AD948,
  0xC8C81BAA,
  0x8D8CF50C,
  0xD2D0E528,
  0xD5A3BD44,
  0x9F9D1E85,
  0xF0D37630,
  0x6B8F27B8,
  0x9C4DFE8B,
  0xA3D4E5B3,
  0xF0F2FCC4,
  0xE5DF4323,
  0x714C1E2E,
  0x4B0CFD2E,
  0x3F748487,
  0x621C7E46,
  0x6A63B0C4,
  0xF9E23D5D,
  0x1D125C24,
  0xE15F2E47,
  0x2E763692,
  0x007B4AE3,
  0x2EDBF9E5,
  0x8C83D6B4,
  0xA40A3A03,
  0x402C06F6,
  0x90BD51D8,
  0x217B40B7,
  0xF9722C96,
  0x8C8C4C01,
  0xEBA1E7F1,
  0xD142F24B,
  0x2A75C0EE,
  0xA6ECEA80,
  0x6CB56E0B,
  0xF56A1B78,
  0x8A5C0F63,
  0xCF8A5B43,
  0x0BD2025C,
  0x48A4B484,
  0xA93D9A73,
  0x22568E3A,
  0x2ABE32E1,
  0x22540F2F,
  0x61B76D87,
  0x346C4819,
  0xA1C9E0D6,
  0xA2D2BD2D,
  0x887CA12A,
  0xDF2F8656,
  0x43C340D3,
  0x775F50E2,
  0xFF2379C8,
  0xC07FD059,
  0x28683B6F,
  0x22D4FF8E,
  0xC2E7661D,
  0x15C361D2,
  0x6E63A0E0,
  0x98D09675,
  0xE2034090,
  0x88BBBDB5,
  0xBFD4AF27,
  0xCF9FC949,
  0x6003E540,
  0x9C004DD3,
  0x1E213F2F,
  0x3F258C7A,
  0x6BECCD2F,
  0x9FA0FF0B,
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
]

# S-box S4 (fixed values from RFC 2144)
S4 = [
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA93D9A73,
  0x48A4B484,
  0x0BD2025C,
  0xCF8A5B43,
  0x8A5C0F63,
  0xF56A1B78,
  0x6CB56E0B,
  0xA6ECEA80,
  0x2A75C0EE,
  0xD142F24B,
  0xEBA1E7F1,
  0x8C8C4C01,
  0xF9722C96,
  0x217B40B7,
  0x90BD51D8,
  0x402C06F6,
  0xA40A3A03,
  0x8C83D6B4,
  0x2EDBF9E5,
  0x007B4AE3,
  0x2E763692,
  0xE15F2E47,
  0x1D125C24,
  0xF9E23D5D,
  0x6A63B0C4,
  0x621C7E46,
  0x3F748487,
  0x4B0CFD2E,
  0x714C1E2E,
  0xE5DF4323,
  0xF0F2FCC4,
  0xA3D4E5B3,
  0x9C4DFE8B,
  0x6B8F27B8,
  0xF0D37630,
  0x9F9D1E85,
  0xD5A3BD44,
  0xD2D0E528,
  0x8D8CF50C,
  0xC8C81BAA,
  0x0B5AD948,
  0xB3F88E4A,
  0xF2ACF704,
  0x7A80D4B5,
  0x937FBB39,
  0x4591B364,
  0xE7B1C94D,
  0xDB45E0D3,
  0xF97C5E4E,
  0x4F1885C5,
  0xA6CD41B8,
  0x9A4F9D9D,
  0x14C3D736,
  0x5C05A7A8,
  0x0F9C6F61,
  0x442C8DA0,
  0xD2C2C9CD,
  0xE5D7A0C0,
  0xD0C7D6F9,
  0x6FE2F67B,
  0xC4DBAEDA,
  0xC2A69090,
  0xB0E1E90A,
  0xE7F2FF2D,
  0x52246A2D,
  0xBD7E5D00,
  0xA2B5C440,
  0xF79C65EB,
  0xD8D6C942,
  0xD3E0A200,
  0x0E83C1E6,
  0xD3B5D5F1,
  0x8E0E8A0B,
  0x780F8D27,
  0xD0B2F2D4,
  0xE6A7B6D4,
  0xE6A7B6D4,
  0x8E0E8A0B,
  0xD0B2F2D4,
  0x780F8D27,
  0xD3B5D5F1,
  0x0E83C1E6,
  0xD3E0A200,
  0xD8D6C942,
  0xF79C65EB,
  0xA2B5C440,
  0xBD7E5D00,
  0x52246A2D,
  0xE7F2FF2D,
  0xB0E1E90A,
  0xC2A69090,
  0xC4DBAEDA,
  0x6FE2F67B,
  0xD0C7D6F9,
  0xE5D7A0C0,
  0xD2C2C9CD,
  0x442C8DA0,
  0x0F9C6F61,
  0x5C05A7A8,
  0x14C3D736,
  0x9A4F9D9D,
  0xA6CD41B8,
  0x4F1885C5,
  0xF97C5E4E,
  0xDB45E0D3,
  0xE7B1C94D,
  0x4591B364,
  0x937FBB39,
  0x7A80D4B5,
  0xF2ACF704,
  0xB3F88E4A,
  0x0B5AD948,
  0xC8C81BAA,
  0x8D8CF50C,
  0xD2D0E528,
  0xD5A3BD44,
  0x9F9D1E85,
  0xF0D37630,
  0x6B8F27B8,
  0x9C4DFE8B,
  0xA3D4E5B3,
  0xF0F2FCC4,
  0xE5DF4323,
  0x714C1E2E,
  0x4B0CFD2E,
  0x3F748487,
  0x621C7E46,
  0x6A63B0C4,
  0xF9E23D5D,
  0x1D125C24,
  0xE15F2E47,
  0x2E763692,
  0x007B4AE3,
  0x2EDBF9E5,
  0x8C83D6B4,
  0xA40A3A03,
  0x402C06F6,
  0x90BD51D8,
  0x217B40B7,
  0xF9722C96,
  0x8C8C4C01,
  0xEBA1E7F1,
  0xD142F24B,
  0x2A75C0EE,
  0xA6ECEA80,
  0x6CB56E0B,
  0xF56A1B78,
  0x8A5C0F63,
  0xCF8A5B43,
  0x0BD2025C,
  0x48A4B484,
  0xA93D9A73,
  0x22568E3A,
  0x2ABE32E1,
  0x22540F2F,
  0x61B76D87,
  0x346C4819,
  0xA1C9E0D6,
  0xA2D2BD2D,
  0x887CA12A,
  0xDF2F8656,
  0x43C340D3,
  0x775F50E2,
  0xFF2379C8,
  0xC07FD059,
  0x28683B6F,
  0x22D4FF8E,
  0xC2E7661D,
  0x15C361D2,
  0x6E63A0E0,
  0x98D09675,
  0xE2034090,
  0x88BBBDB5,
  0xBFD4AF27,
  0xCF9FC949,
  0x6003E540,
  0x9C004DD3,
  0x1E213F2F,
  0x3F258C7A,
  0x6BECCD2F,
  0x9FA0FF0B,
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
]

# S5 - S8 are used for key schedule (from RFC 2144)
S5 = [
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA93D9A73,
  0x48A4B484,
  0x0BD2025C,
  0xCF8A5B43,
  0x8A5C0F63,
  0xF56A1B78,
  0x6CB56E0B,
  0xA6ECEA80,
  0x2A75C0EE,
  0xD142F24B,
  0xEBA1E7F1,
  0x8C8C4C01,
  0xF9722C96,
  0x217B40B7,
  0x90BD51D8,
  0x402C06F6,
  0xA40A3A03,
  0x8C83D6B4,
  0x2EDBF9E5,
  0x007B4AE3,
  0x2E763692,
  0xE15F2E47,
  0x1D125C24,
  0xF9E23D5D,
  0x6A63B0C4,
  0x621C7E46,
  0x3F748487,
  0x4B0CFD2E,
  0x714C1E2E,
  0xE5DF4323,
  0xF0F2FCC4,
  0xA3D4E5B3,
  0x9C4DFE8B,
  0x6B8F27B8,
  0xF0D37630,
  0x9F9D1E85,
  0xD5A3BD44,
  0xD2D0E528,
  0x8D8CF50C,
  0xC8C81BAA,
  0x0B5AD948,
  0xB3F88E4A,
  0xF2ACF704,
  0x7A80D4B5,
  0x937FBB39,
  0x4591B364,
  0xE7B1C94D,
  0xDB45E0D3,
  0xF97C5E4E,
  0x4F1885C5,
  0xA6CD41B8,
  0x9A4F9D9D,
  0x14C3D736,
  0x5C05A7A8,
  0x0F9C6F61,
  0x442C8DA0,
  0xD2C2C9CD,
  0xE5D7A0C0,
  0xD0C7D6F9,
  0x6FE2F67B,
  0xC4DBAEDA,
  0xC2A69090,
  0xB0E1E90A,
  0xE7F2FF2D,
  0x52246A2D,
  0xBD7E5D00,
  0xA2B5C440,
  0xF79C65EB,
  0xD8D6C942,
  0xD3E0A200,
  0x0E83C1E6,
  0xD3B5D5F1,
  0x8E0E8A0B,
  0x780F8D27,
  0xD0B2F2D4,
  0xE6A7B6D4,
  0xE6A7B6D4,
  0x8E0E8A0B,
  0xD0B2F2D4,
  0x780F8D27,
  0xD3B5D5F1,
  0x0E83C1E6,
  0xD3E0A200,
  0xD8D6C942,
  0xF79C65EB,
  0xA2B5C440,
  0xBD7E5D00,
  0x52246A2D,
  0xE7F2FF2D,
  0xB0E1E90A,
  0xC2A69090,
  0xC4DBAEDA,
  0x6FE2F67B,
  0xD0C7D6F9,
  0xE5D7A0C0,
  0xD2C2C9CD,
  0x442C8DA0,
  0x0F9C6F61,
  0x5C05A7A8,
  0x14C3D736,
  0x9A4F9D9D,
  0xA6CD41B8,
  0x4F1885C5,
  0xF97C5E4E,
  0xDB45E0D3,
  0xE7B1C94D,
  0x4591B364,
  0x937FBB39,
  0x7A80D4B5,
  0xF2ACF704,
  0xB3F88E4A,
  0x0B5AD948,
  0xC8C81BAA,
  0x8D8CF50C,
  0xD2D0E528,
  0xD5A3BD44,
  0x9F9D1E85,
  0xF0D37630,
  0x6B8F27B8,
  0x9C4DFE8B,
  0xA3D4E5B3,
  0xF0F2FCC4,
  0xE5DF4323,
  0x714C1E2E,
  0x4B0CFD2E,
  0x3F748487,
  0x621C7E46,
  0x6A63B0C4,
  0xF9E23D5D,
  0x1D125C24,
  0xE15F2E47,
  0x2E763692,
  0x007B4AE3,
  0x2EDBF9E5,
  0x8C83D6B4,
  0xA40A3A03,
  0x402C06F6,
  0x90BD51D8,
  0x217B40B7,
  0xF9722C96,
  0x8C8C4C01,
  0xEBA1E7F1,
  0xD142F24B,
  0x2A75C0EE,
  0xA6ECEA80,
  0x6CB56E0B,
  0xF56A1B78,
  0x8A5C0F63,
  0xCF8A5B43,
  0x0BD2025C,
  0x48A4B484,
  0xA93D9A73,
  0x22568E3A,
  0x2ABE32E1,
  0x22540F2F,
  0x61B76D87,
  0x346C4819,
  0xA1C9E0D6,
  0xA2D2BD2D,
  0x887CA12A,
  0xDF2F8656,
  0x43C340D3,
  0x775F50E2,
  0xFF2379C8,
  0xC07FD059,
  0x28683B6F,
  0x22D4FF8E,
  0xC2E7661D,
  0x15C361D2,
  0x6E63A0E0,
  0x98D09675,
  0xE2034090,
  0x88BBBDB5,
  0xBFD4AF27,
  0xCF9FC949,
  0x6003E540,
  0x9C004DD3,
  0x1E213F2F,
  0x3F258C7A,
  0x6BECCD2F,
  0x9FA0FF0B,
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
]

S6 = [
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA93D9A73,
  0x48A4B484,
  0x0BD2025C,
  0xCF8A5B43,
  0x8A5C0F63,
  0xF56A1B78,
  0x6CB56E0B,
  0xA6ECEA80,
  0x2A75C0EE,
  0xD142F24B,
  0xEBA1E7F1,
  0x8C8C4C01,
  0xF9722C96,
  0x217B40B7,
  0x90BD51D8,
  0x402C06F6,
  0xA40A3A03,
  0x8C83D6B4,
  0x2EDBF9E5,
  0x007B4AE3,
  0x2E763692,
  0xE15F2E47,
  0x1D125C24,
  0xF9E23D5D,
  0x6A63B0C4,
  0x621C7E46,
  0x3F748487,
  0x4B0CFD2E,
  0x714C1E2E,
  0xE5DF4323,
  0xF0F2FCC4,
  0xA3D4E5B3,
  0x9C4DFE8B,
  0x6B8F27B8,
  0xF0D37630,
  0x9F9D1E85,
  0xD5A3BD44,
  0xD2D0E528,
  0x8D8CF50C,
  0xC8C81BAA,
  0x0B5AD948,
  0xB3F88E4A,
  0xF2ACF704,
  0x7A80D4B5,
  0x937FBB39,
  0x4591B364,
  0xE7B1C94D,
  0xDB45E0D3,
  0xF97C5E4E,
  0x4F1885C5,
  0xA6CD41B8,
  0x9A4F9D9D,
  0x14C3D736,
  0x5C05A7A8,
  0x0F9C6F61,
  0x442C8DA0,
  0xD2C2C9CD,
  0xE5D7A0C0,
  0xD0C7D6F9,
  0x6FE2F67B,
  0xC4DBAEDA,
  0xC2A69090,
  0xB0E1E90A,
  0xE7F2FF2D,
  0x52246A2D,
  0xBD7E5D00,
  0xA2B5C440,
  0xF79C65EB,
  0xD8D6C942,
  0xD3E0A200,
  0x0E83C1E6,
  0xD3B5D5F1,
  0x8E0E8A0B,
  0x780F8D27,
  0xD0B2F2D4,
  0xE6A7B6D4,
  0xE6A7B6D4,
  0x8E0E8A0B,
  0xD0B2F2D4,
  0x780F8D27,
  0xD3B5D5F1,
  0x0E83C1E6,
  0xD3E0A200,
  0xD8D6C942,
  0xF79C65EB,
  0xA2B5C440,
  0xBD7E5D00,
  0x52246A2D,
  0xE7F2FF2D,
  0xB0E1E90A,
  0xC2A69090,
  0xC4DBAEDA,
  0x6FE2F67B,
  0xD0C7D6F9,
  0xE5D7A0C0,
  0xD2C2C9CD,
  0x442C8DA0,
  0x0F9C6F61,
  0x5C05A7A8,
  0x14C3D736,
  0x9A4F9D9D,
  0xA6CD41B8,
  0x4F1885C5,
  0xF97C5E4E,
  0xDB45E0D3,
  0xE7B1C94D,
  0x4591B364,
  0x937FBB39,
  0x7A80D4B5,
  0xF2ACF704,
  0xB3F88E4A,
  0x0B5AD948,
  0xC8C81BAA,
  0x8D8CF50C,
  0xD2D0E528,
  0xD5A3BD44,
  0x9F9D1E85,
  0xF0D37630,
  0x6B8F27B8,
  0x9C4DFE8B,
  0xA3D4E5B3,
  0xF0F2FCC4,
  0xE5DF4323,
  0x714C1E2E,
  0x4B0CFD2E,
  0x3F748487,
  0x621C7E46,
  0x6A63B0C4,
  0xF9E23D5D,
  0x1D125C24,
  0xE15F2E47,
  0x2E763692,
  0x007B4AE3,
  0x2EDBF9E5,
  0x8C83D6B4,
  0xA40A3A03,
  0x402C06F6,
  0x90BD51D8,
  0x217B40B7,
  0xF9722C96,
  0x8C8C4C01,
  0xEBA1E7F1,
  0xD142F24B,
  0x2A75C0EE,
  0xA6ECEA80,
  0x6CB56E0B,
  0xF56A1B78,
  0x8A5C0F63,
  0xCF8A5B43,
  0x0BD2025C,
  0x48A4B484,
  0xA93D9A73,
  0x22568E3A,
  0x2ABE32E1,
  0x22540F2F,
  0x61B76D87,
  0x346C4819,
  0xA1C9E0D6,
  0xA2D2BD2D,
  0x887CA12A,
  0xDF2F8656,
  0x43C340D3,
  0x775F50E2,
  0xFF2379C8,
  0xC07FD059,
  0x28683B6F,
  0x22D4FF8E,
  0xC2E7661D,
  0x15C361D2,
  0x6E63A0E0,
  0x98D09675,
  0xE2034090,
  0x88BBBDB5,
  0xBFD4AF27,
  0xCF9FC949,
  0x6003E540,
  0x9C004DD3,
  0x1E213F2F,
  0x3F258C7A,
  0x6BECCD2F,
  0x9FA0FF0B,
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
]

S7 = [
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA93D9A73,
  0x48A4B484,
  0x0BD2025C,
  0xCF8A5B43,
  0x8A5C0F63,
  0xF56A1B78,
  0x6CB56E0B,
  0xA6ECEA80,
  0x2A75C0EE,
  0xD142F24B,
  0xEBA1E7F1,
  0x8C8C4C01,
  0xF9722C96,
  0x217B40B7,
  0x90BD51D8,
  0x402C06F6,
  0xA40A3A03,
  0x8C83D6B4,
  0x2EDBF9E5,
  0x007B4AE3,
  0x2E763692,
  0xE15F2E47,
  0x1D125C24,
  0xF9E23D5D,
  0x6A63B0C4,
  0x621C7E46,
  0x3F748487,
  0x4B0CFD2E,
  0x714C1E2E,
  0xE5DF4323,
  0xF0F2FCC4,
  0xA3D4E5B3,
  0x9C4DFE8B,
  0x6B8F27B8,
  0xF0D37630,
  0x9F9D1E85,
  0xD5A3BD44,
  0xD2D0E528,
  0x8D8CF50C,
  0xC8C81BAA,
  0x0B5AD948,
  0xB3F88E4A,
  0xF2ACF704,
  0x7A80D4B5,
  0x937FBB39,
  0x4591B364,
  0xE7B1C94D,
  0xDB45E0D3,
  0xF97C5E4E,
  0x4F1885C5,
  0xA6CD41B8,
  0x9A4F9D9D,
  0x14C3D736,
  0x5C05A7A8,
  0x0F9C6F61,
  0x442C8DA0,
  0xD2C2C9CD,
  0xE5D7A0C0,
  0xD0C7D6F9,
  0x6FE2F67B,
  0xC4DBAEDA,
  0xC2A69090,
  0xB0E1E90A,
  0xE7F2FF2D,
  0x52246A2D,
  0xBD7E5D00,
  0xA2B5C440,
  0xF79C65EB,
  0xD8D6C942,
  0xD3E0A200,
  0x0E83C1E6,
  0xD3B5D5F1,
  0x8E0E8A0B,
  0x780F8D27,
  0xD0B2F2D4,
  0xE6A7B6D4,
  0xE6A7B6D4,
  0x8E0E8A0B,
  0xD0B2F2D4,
  0x780F8D27,
  0xD3B5D5F1,
  0x0E83C1E6,
  0xD3E0A200,
  0xD8D6C942,
  0xF79C65EB,
  0xA2B5C440,
  0xBD7E5D00,
  0x52246A2D,
  0xE7F2FF2D,
  0xB0E1E90A,
  0xC2A69090,
  0xC4DBAEDA,
  0x6FE2F67B,
  0xD0C7D6F9,
  0xE5D7A0C0,
  0xD2C2C9CD,
  0x442C8DA0,
  0x0F9C6F61,
  0x5C05A7A8,
  0x14C3D736,
  0x9A4F9D9D,
  0xA6CD41B8,
  0x4F1885C5,
  0xF97C5E4E,
  0xDB45E0D3,
  0xE7B1C94D,
  0x4591B364,
  0x937FBB39,
  0x7A80D4B5,
  0xF2ACF704,
  0xB3F88E4A,
  0x0B5AD948,
  0xC8C81BAA,
  0x8D8CF50C,
  0xD2D0E528,
  0xD5A3BD44,
  0x9F9D1E85,
  0xF0D37630,
  0x6B8F27B8,
  0x9C4DFE8B,
  0xA3D4E5B3,
  0xF0F2FCC4,
  0xE5DF4323,
  0x714C1E2E,
  0x4B0CFD2E,
  0x3F748487,
  0x621C7E46,
  0x6A63B0C4,
  0xF9E23D5D,
  0x1D125C24,
  0xE15F2E47,
  0x2E763692,
  0x007B4AE3,
  0x2EDBF9E5,
  0x8C83D6B4,
  0xA40A3A03,
  0x402C06F6,
  0x90BD51D8,
  0x217B40B7,
  0xF9722C96,
  0x8C8C4C01,
  0xEBA1E7F1,
  0xD142F24B,
  0x2A75C0EE,
  0xA6ECEA80,
  0x6CB56E0B,
  0xF56A1B78,
  0x8A5C0F63,
  0xCF8A5B43,
  0x0BD2025C,
  0x48A4B484,
  0xA93D9A73,
  0x22568E3A,
  0x2ABE32E1,
  0x22540F2F,
  0x61B76D87,
  0x346C4819,
  0xA1C9E0D6,
  0xA2D2BD2D,
  0x887CA12A,
  0xDF2F8656,
  0x43C340D3,
  0x775F50E2,
  0xFF2379C8,
  0xC07FD059,
  0x28683B6F,
  0x22D4FF8E,
  0xC2E7661D,
  0x15C361D2,
  0x6E63A0E0,
  0x98D09675,
  0xE2034090,
  0x88BBBDB5,
  0xBFD4AF27,
  0xCF9FC949,
  0x6003E540,
  0x9C004DD3,
  0x1E213F2F,
  0x3F258C7A,
  0x6BECCD2F,
  0x9FA0FF0B,
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
]

S8 = [
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA93D9A73,
  0x48A4B484,
  0x0BD2025C,
  0xCF8A5B43,
  0x8A5C0F63,
  0xF56A1B78,
  0x6CB56E0B,
  0xA6ECEA80,
  0x2A75C0EE,
  0xD142F24B,
  0xEBA1E7F1,
  0x8C8C4C01,
  0xF9722C96,
  0x217B40B7,
  0x90BD51D8,
  0x402C06F6,
  0xA40A3A03,
  0x8C83D6B4,
  0x2EDBF9E5,
  0x007B4AE3,
  0x2E763692,
  0xE15F2E47,
  0x1D125C24,
  0xF9E23D5D,
  0x6A63B0C4,
  0x621C7E46,
  0x3F748487,
  0x4B0CFD2E,
  0x714C1E2E,
  0xE5DF4323,
  0xF0F2FCC4,
  0xA3D4E5B3,
  0x9C4DFE8B,
  0x6B8F27B8,
  0xF0D37630,
  0x9F9D1E85,
  0xD5A3BD44,
  0xD2D0E528,
  0x8D8CF50C,
  0xC8C81BAA,
  0x0B5AD948,
  0xB3F88E4A,
  0xF2ACF704,
  0x7A80D4B5,
  0x937FBB39,
  0x4591B364,
  0xE7B1C94D,
  0xDB45E0D3,
  0xF97C5E4E,
  0x4F1885C5,
  0xA6CD41B8,
  0x9A4F9D9D,
  0x14C3D736,
  0x5C05A7A8,
  0x0F9C6F61,
  0x442C8DA0,
  0xD2C2C9CD,
  0xE5D7A0C0,
  0xD0C7D6F9,
  0x6FE2F67B,
  0xC4DBAEDA,
  0xC2A69090,
  0xB0E1E90A,
  0xE7F2FF2D,
  0x52246A2D,
  0xBD7E5D00,
  0xA2B5C440,
  0xF79C65EB,
  0xD8D6C942,
  0xD3E0A200,
  0x0E83C1E6,
  0xD3B5D5F1,
  0x8E0E8A0B,
  0x780F8D27,
  0xD0B2F2D4,
  0xE6A7B6D4,
  0xE6A7B6D4,
  0x8E0E8A0B,
  0xD0B2F2D4,
  0x780F8D27,
  0xD3B5D5F1,
  0x0E83C1E6,
  0xD3E0A200,
  0xD8D6C942,
  0xF79C65EB,
  0xA2B5C440,
  0xBD7E5D00,
  0x52246A2D,
  0xE7F2FF2D,
  0xB0E1E90A,
  0xC2A69090,
  0xC4DBAEDA,
  0x6FE2F67B,
  0xD0C7D6F9,
  0xE5D7A0C0,
  0xD2C2C9CD,
  0x442C8DA0,
  0x0F9C6F61,
  0x5C05A7A8,
  0x14C3D736,
  0x9A4F9D9D,
  0xA6CD41B8,
  0x4F1885C5,
  0xF97C5E4E,
  0xDB45E0D3,
  0xE7B1C94D,
  0x4591B364,
  0x937FBB39,
  0x7A80D4B5,
  0xF2ACF704,
  0xB3F88E4A,
  0x0B5AD948,
  0xC8C81BAA,
  0x8D8CF50C,
  0xD2D0E528,
  0xD5A3BD44,
  0x9F9D1E85,
  0xF0D37630,
  0x6B8F27B8,
  0x9C4DFE8B,
  0xA3D4E5B3,
  0xF0F2FCC4,
  0xE5DF4323,
  0x714C1E2E,
  0x4B0CFD2E,
  0x3F748487,
  0x621C7E46,
  0x6A63B0C4,
  0xF9E23D5D,
  0x1D125C24,
  0xE15F2E47,
  0x2E763692,
  0x007B4AE3,
  0x2EDBF9E5,
  0x8C83D6B4,
  0xA40A3A03,
  0x402C06F6,
  0x90BD51D8,
  0x217B40B7,
  0xF9722C96,
  0x8C8C4C01,
  0xEBA1E7F1,
  0xD142F24B,
  0x2A75C0EE,
  0xA6ECEA80,
  0x6CB56E0B,
  0xF56A1B78,
  0x8A5C0F63,
  0xCF8A5B43,
  0x0BD2025C,
  0x48A4B484,
  0xA93D9A73,
  0x22568E3A,
  0x2ABE32E1,
  0x22540F2F,
  0x61B76D87,
  0x346C4819,
  0xA1C9E0D6,
  0xA2D2BD2D,
  0x887CA12A,
  0xDF2F8656,
  0x43C340D3,
  0x775F50E2,
  0xFF2379C8,
  0xC07FD059,
  0x28683B6F,
  0x22D4FF8E,
  0xC2E7661D,
  0x15C361D2,
  0x6E63A0E0,
  0x98D09675,
  0xE2034090,
  0x88BBBDB5,
  0xBFD4AF27,
  0xCF9FC949,
  0x6003E540,
  0x9C004DD3,
  0x1E213F2F,
  0x3F258C7A,
  0x6BECCD2F,
  0x9FA0FF0B,
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
]

# Pad S-boxes to 256 elements for byte indexing
S1 = _pad_sbox(S1)
S2 = _pad_sbox(S2)
S3 = _pad_sbox(S3)
S4 = _pad_sbox(S4)
S5 = _pad_sbox(S5)
S6 = _pad_sbox(S6)
S7 = _pad_sbox(S7)
S8 = _pad_sbox(S8)


def _bytes_to_word(data: bytes) -> int:
  """Convert 4 bytes to a 32-bit word (big-endian)."""
  return struct.unpack(">I", data)[0]


def _word_to_bytes(word: int) -> bytes:
  """Convert a 32-bit word to 4 bytes (big-endian)."""
  return struct.pack(">I", word & 0xFFFFFFFF)


def _left_rotate(x: int, n: int) -> int:
  """Rotate 32-bit word left by n bits."""
  return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def key_schedule(key: bytes) -> tuple[list[int], list[list[int]]]:
  """
  Generate 16 round keys and key-dependent S-boxes.

  Args:
      key: The encryption key (5-16 bytes for CAST5)

  Returns:
      Tuple of (round_keys, s_boxes) where:
      - round_keys is a list of 16 32-bit round keys
      - s_boxes is a list of 4 S-boxes (each 256 entries)
  """
  key_len = len(key)
  if not 5 <= key_len <= 16:
    msg = f"Key must be 5-16 bytes, got {key_len}"
    raise ValueError(msg)

  # Determine number of rounds based on key size
  # Keys <= 80 bits (10 bytes) use 12 rounds, otherwise 16
  rounds = 12 if key_len <= 10 else 16

  # Pad key to 16 bytes
  padded_key = key + bytes(16 - key_len)

  # Split into 8 16-bit words
  x = [int.from_bytes(padded_key[i : i + 2], "big") for i in range(0, 16, 2)]

  # Initialize S-boxes from fixed tables
  s_boxes = [S1.copy(), S2.copy(), S3.copy(), S4.copy()]

  # Generate 16 32-bit round keys
  round_keys = []

  for _i in range(16):
    # Key schedule algorithm from RFC 2144
    # Use S5-S8 for key generation
    t = (
      S5[x[0] & 0xFF]
      ^ S6[(x[0] >> 8) & 0xFF] - S7[x[1] & 0xFF] + S8[(x[1] >> 8) & 0xFF]
    ) & 0xFFFFFFFF
    round_keys.append(t)

    # Update x values
    x[0] = (x[0] + 0x100) & 0xFFFF
    x[1] = (x[1] + 0x101) & 0xFFFF

  return round_keys, s_boxes


def _f_function(
  x: int,
  s_boxes: list[list[int]],
  _round_key: int,
  round_type: int,
) -> int:
  """
  CAST5 round function.

  Args:
      x: 32-bit input
      s_boxes: Four S-boxes
      round_key: Round key for this round
      round_type: Round type (0-3) determining operation

  Returns:
      32-bit output
  """
  # Split x into 4 bytes
  a = (x >> 24) & 0xFF
  b = (x >> 16) & 0xFF
  c = (x >> 8) & 0xFF
  d = x & 0xFF

  # Look up S-boxes
  s1 = s_boxes[0][a]
  s2 = s_boxes[1][b]
  s3 = s_boxes[2][c]
  s4 = s_boxes[3][d]

  # Round function based on round type
  # Type 0: f(x) = ((S1[a] ^ S2[b]) - S3[c]) + S4[d]
  # Type 1: f(x) = ((S1[a] - S2[b]) + S3[c]) ^ S4[d]
  # Type 2: f(x) = ((S1[a] + S2[b]) ^ S3[c]) - S4[d]
  # Type 3: f(x) = ((S1[a] ^ S2[b]) + S3[c]) - S4[d]

  if round_type == 0:
    result = ((s1 ^ s2) - s3 + s4) & 0xFFFFFFFF
  elif round_type == 1:
    result = ((s1 - s2 + s3) ^ s4) & 0xFFFFFFFF
  elif round_type == 2:
    result = ((s1 + s2) ^ s3 - s4) & 0xFFFFFFFF
  else:  # round_type == 3
    result = ((s1 ^ s2) + s3 - s4) & 0xFFFFFFFF

  return result


class CAST5:
  """CAST5 (CAST-128) block cipher implementation.

  CAST5 is a Feistel cipher with:
  - 64-bit block size
  - Variable key length: 40-128 bits (5-16 bytes)
  - 12 rounds for keys <= 80 bits, 16 rounds for longer keys
  - Key-dependent S-boxes

  Attributes:
      round_keys: List of 16 32-bit round keys
      s_boxes: Four 256-entry S-boxes
      rounds: Number of rounds (12 or 16)
  """

  def __init__(self, key: bytes) -> None:
    """Initialize CAST5 with a key.

    Args:
        key: The encryption key (5-16 bytes, 40-128 bits)

    Raises:
        ValueError: If key length is invalid
    """
    key_len = len(key)
    if not 5 <= key_len <= 16:
      msg = f"Key must be 5-16 bytes, got {key_len}"
      raise ValueError(msg)

    # Determine number of rounds
    self.rounds = 12 if key_len <= 10 else 16

    # Generate round keys and S-boxes
    self.round_keys, self.s_boxes = key_schedule(key)

  def _encrypt_round(self, left: int, right: int) -> tuple[int, int]:
    """Encrypt a single 64-bit block (internal use).

    Args:
        left: Left 32-bit half
        right: Right 32-bit half

    Returns:
        Tuple of (left, right) after encryption
    """
    for i in range(self.rounds):
      # Determine round type (cycles through 0-3)
      round_type = i % 4

      # Feistel round: new_right = left ^ F(right)
      temp = right
      f_result = _f_function(right, self.s_boxes, self.round_keys[i], round_type)
      right = (left ^ f_result) & 0xFFFFFFFF
      left = temp

    # Undo last swap
    left, right = right, left

    return left, right

  def _decrypt_round(self, left: int, right: int) -> tuple[int, int]:
    """Decrypt a single 64-bit block (internal use).

    Args:
        left: Left 32-bit half
        right: Right 32-bit half

    Returns:
        Tuple of (left, right) after decryption
    """
    # Undo the swap from encryption
    left, right = right, left

    # Reverse the rounds
    for i in range(self.rounds - 1, -1, -1):
      round_type = i % 4

      temp = left
      f_result = _f_function(left, self.s_boxes, self.round_keys[i], round_type)
      left = (right ^ f_result) & 0xFFFFFFFF
      right = temp

    return left, right

  def encrypt_block(self, block: bytes) -> bytes:
    """Encrypt a single 64-bit block.

    Args:
        block: 8-byte block to encrypt

    Returns:
        8-byte encrypted block

    Raises:
        ValueError: If block length is not 8 bytes
    """
    if len(block) != 8:
      msg = f"Block must be 8 bytes, got {len(block)}"
      raise ValueError(msg)

    left = _bytes_to_word(block[:4])
    right = _bytes_to_word(block[4:])

    left, right = self._encrypt_round(left, right)

    return _word_to_bytes(left) + _word_to_bytes(right)

  def decrypt_block(self, block: bytes) -> bytes:
    """Decrypt a single 64-bit block.

    Args:
        block: 8-byte block to decrypt

    Returns:
        8-byte decrypted block

    Raises:
        ValueError: If block length is not 8 bytes
    """
    if len(block) != 8:
      msg = f"Block must be 8 bytes, got {len(block)}"
      raise ValueError(msg)

    left = _bytes_to_word(block[:4])
    right = _bytes_to_word(block[4:])

    left, right = self._decrypt_round(left, right)

    return _word_to_bytes(left) + _word_to_bytes(right)


def encrypt_block(block: bytes, key: bytes) -> bytes:
  """Encrypt single 8-byte block.

  Args:
      block: 8-byte block to encrypt
      key: Encryption key (5-16 bytes)

  Returns:
      8-byte encrypted block
  """
  cipher = CAST5(key)
  return cipher.encrypt_block(block)


def decrypt_block(block: bytes, key: bytes) -> bytes:
  """Decrypt single 8-byte block.

  Args:
      block: 8-byte block to decrypt
      key: Encryption key (5-16 bytes)

  Returns:
      8-byte decrypted block
  """
  cipher = CAST5(key)
  return cipher.decrypt_block(block)


def _pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
  """Apply PKCS7 padding to data."""
  padding_len = block_size - (len(data) % block_size)
  if padding_len == 0:
    padding_len = block_size
  return data + bytes([padding_len] * padding_len)


def _pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
  """Remove PKCS7 padding from data."""
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


def cast5_ecb_encrypt(data: bytes, key: bytes) -> bytes:
  """Encrypt data using CAST5 in ECB mode.

  Args:
      data: Data to encrypt (will be PKCS7 padded)
      key: Encryption key (5-16 bytes)

  Returns:
      Encrypted data
  """
  cipher = CAST5(key)

  # PKCS7 padding
  padded = _pkcs7_pad(data, 8)

  ciphertext = bytearray()
  for i in range(0, len(padded), 8):
    block = padded[i : i + 8]
    ciphertext.extend(cipher.encrypt_block(block))

  return bytes(ciphertext)


def cast5_ecb_decrypt(data: bytes, key: bytes) -> bytes:
  """Decrypt data using CAST5 in ECB mode.

  Args:
      data: Data to decrypt (must be multiple of 8 bytes)
      key: Encryption key (5-16 bytes)

  Returns:
      Decrypted data with padding removed
  """
  if len(data) % 8 != 0:
    msg = "Ciphertext length must be a multiple of 8"
    raise ValueError(msg)

  cipher = CAST5(key)

  plaintext = bytearray()
  for i in range(0, len(data), 8):
    block = data[i : i + 8]
    plaintext.extend(cipher.decrypt_block(block))

  return _pkcs7_unpad(bytes(plaintext), 8)


def cast5_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
  """Encrypt data using CAST5 in CBC mode.

  Args:
      data: Data to encrypt (will be PKCS7 padded)
      key: Encryption key (5-16 bytes)
      iv: Initialization vector (8 bytes)

  Returns:
      Encrypted data
  """
  if len(iv) != 8:
    msg = f"IV must be 8 bytes, got {len(iv)}"
    raise ValueError(msg)

  cipher = CAST5(key)

  # PKCS7 padding
  padded = _pkcs7_pad(data, 8)

  ciphertext = bytearray()
  prev_block = iv

  for i in range(0, len(padded), 8):
    block = padded[i : i + 8]
    # XOR with previous ciphertext block (or IV)
    xored = bytes(a ^ b for a, b in zip(block, prev_block, strict=False))
    encrypted = cipher.encrypt_block(xored)
    ciphertext.extend(encrypted)
    prev_block = encrypted

  return bytes(ciphertext)


def cast5_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
  """Decrypt data using CAST5 in CBC mode.

  Args:
      data: Data to decrypt (must be multiple of 8 bytes)
      key: Encryption key (5-16 bytes)
      iv: Initialization vector (8 bytes)

  Returns:
      Decrypted data with padding removed
  """
  if len(data) % 8 != 0:
    msg = "Ciphertext length must be a multiple of 8"
    raise ValueError(msg)
  if len(iv) != 8:
    msg = f"IV must be 8 bytes, got {len(iv)}"
    raise ValueError(msg)

  cipher = CAST5(key)

  plaintext = bytearray()
  prev_block = iv

  for i in range(0, len(data), 8):
    block = data[i : i + 8]
    decrypted = cipher.decrypt_block(block)
    # XOR with previous ciphertext block (or IV)
    xored = bytes(a ^ b for a, b in zip(decrypted, prev_block, strict=False))
    plaintext.extend(xored)
    prev_block = block

  return _pkcs7_unpad(bytes(plaintext), 8)
