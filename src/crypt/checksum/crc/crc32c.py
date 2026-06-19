"""CRC-32C (Castagnoli) implementation.

CRC-32C uses polynomial 0x1EDC6F41.
Used in:
- iSCSI (Internet Small Computer Systems Interface)
- SCTP (Stream Control Transmission Protocol)
- Btrfs (file system)
- Intel SSE4.2 hardware acceleration
"""


def _reflect32(value: int) -> int:
  """Reflect 32 bits."""
  result = 0
  for i in range(32):
    result = (result << 1) | ((value >> i) & 1)
  return result


def crc32c(
  data: bytes,
  init: int = 0xFFFFFFFF,
  *,
  xor_out: int = 0xFFFFFFFF,
) -> int:
  """Generic CRC-32C (Castagnoli) calculation function.

  Uses polynomial 0x1EDC6F41 with bit reflection.

  Args:
      data: Input byte data
      init: Initial value (typically 0xFFFFFFFF)
      xor_out: Final XOR value (typically 0xFFFFFFFF)

  Returns:
      CRC-32C checksum (0-4294967295)
  """
  # CRC-32C uses reflected mode (ref_in=true, ref_out=true)
  # Polynomial 0x1EDC6F41 in reflected form
  poly_ref = 0x82F63B78  # Reflected 0x1EDC6F41

  # Generate CRC lookup table with bit reflection
  crc_table = [0] * 256
  for i in range(256):
    crc = i
    for _ in range(8):
      if crc & 1:
        crc = (crc >> 1) ^ poly_ref
      else:
        crc >>= 1
    crc_table[i] = crc

  # Initialize CRC value
  crc = init

  # Process each byte
  for byte in data:
    crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8)

  return (crc ^ xor_out) & 0xFFFFFFFF


def crc32c_castagnoli(data: bytes) -> int:
  """CRC-32C (Castagnoli) standard variant.

  poly=0x1EDC6F41 init=0xFFFFFFFF refin=true refout=true xorout=0xFFFFFFFF
  Used in iSCSI, SCTP, Btrfs.

  Test vector: crc32c(b"123456789") == 0xE3069283
  """
  return crc32c(data, init=0xFFFFFFFF, xor_out=0xFFFFFFFF)


def crc32c_iscsi(data: bytes) -> int:
  """CRC-32C for iSCSI protocol.

  Alias for crc32c_castagnoli.
  """
  return crc32c_castagnoli(data)


def crc32c_sctp(data: bytes) -> int:
  """CRC-32C for SCTP protocol.

  Alias for crc32c_castagnoli.
  """
  return crc32c_castagnoli(data)
