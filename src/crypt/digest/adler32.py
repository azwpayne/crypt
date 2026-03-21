"""Adler-32 checksum — pure Python implementation.

Adler-32 is a checksum algorithm invented by Mark Adler.
It produces a 32-bit checksum by combining two 16-bit sums.
Much faster than CRC-32 with similar error-detection strength.
"""

MOD_ADLER = 65521  # largest prime smaller than 2^16


def adler32(data: bytes, value: int = 1) -> int:
  """Compute Adler-32 checksum.

  Args:
      data : bytes to checksum
      value: initial checksum value (default 1, can chain calls)

  Returns:
      32-bit unsigned integer checksum
  """
  a = value & 0xFFFF
  b = (value >> 16) & 0xFFFF
  for byte in data:
    a = (a + byte) % MOD_ADLER
    b = (b + a) % MOD_ADLER
  return (b << 16) | a


def adler32_hex(data: bytes, value: int = 1) -> str:
  """Return Adler-32 checksum as an 8-character lowercase hex string."""
  return f"{adler32(data, value):08x}"
