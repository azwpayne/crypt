"""CRC-64/ECMA-182 checksum — pure Python implementation.

Polynomial : 0xAD93D23594C935A9 (reversed: 0x42F0E1EBA9EA3693)
Init       : 0x0000000000000000
RefIn      : False
RefOut     : False
XorOut     : 0x0000000000000000

Known vector: CRC-64(b"123456789") == 0x6C40DF5F0B497347
"""

POLY = 0x42F0E1EBA9EA3693  # normal (non-reflected) polynomial
MASK = 0xFFFFFFFFFFFFFFFF


def _build_table() -> list:
  table = []
  for i in range(256):
    crc = i << 56
    for _ in range(8):
      if crc & (1 << 63):
        crc = (crc << 1) ^ POLY
      else:
        crc <<= 1
      crc &= MASK
    table.append(crc)
  return table


_TABLE = _build_table()


def crc64(data: bytes, init: int = 0) -> int:
  """Compute CRC-64/ECMA-182 checksum.

  Args:
      data: bytes to checksum
      init: initial CRC value (default 0)

  Returns:
      64-bit unsigned integer checksum
  """
  crc = init & MASK
  for byte in data:
    crc = ((crc << 8) & MASK) ^ _TABLE[(crc >> 56) ^ byte]
  return crc


def crc64_hex(data: bytes) -> str:
  """Return CRC-64 checksum as a 16-character lowercase hex string."""
  return f"{crc64(data):016x}"
