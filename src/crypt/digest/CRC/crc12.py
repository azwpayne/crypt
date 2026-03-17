"""CRC-12 implementation.

CRC-12 is a 12-bit cyclic redundancy check.
Common variants:
- CRC-12/UMTS (Telecom)
- CRC-12/CDMA2000 (Telecom)
- CRC-12/DECT (Digital Enhanced Cordless Telecommunications)
"""


def crc12(
        data: bytes,
        poly: int = 0x80F,
        init: int = 0x000,
        *,
        ref_in: bool = False,
        ref_out: bool = False,
        xor_out: int = 0x000,
) -> int:
    """Generic CRC-12 calculation function.

    CRC-12 is stored in the upper 12 bits of a 16-bit internal register.

    Args:
        data: Input byte data
        poly: Polynomial (e.g., 0x80F, 0xF13)
        init: Initial value (typically 0x000 or 0xFFF)
        ref_in: Whether to reverse input bits
        ref_out: Whether to reverse output bits
        xor_out: Final XOR value

    Returns:
        CRC-12 checksum (0-4095)
    """
    # CRC-12 uses 12 bits stored in the MSB of a 16-bit register
    # Align 12-bit values to upper 16 bits
    crc = (init & 0xFFF) << 4
    poly_16 = (poly & 0xFFF) << 4

    if ref_in:
        # Reflected mode (LSB first)
        for byte in data:
            byte = _reflect8(byte)
            crc ^= byte << 8
            for _ in range(8):
                crc = (crc << 1 ^ poly_16) & 65535 if crc & 32768 else crc << 1 & 65535
    else:
        # Non-reflected mode (MSB first)
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                crc = (crc << 1 ^ poly_16) & 65535 if crc & 32768 else crc << 1 & 65535

    # Extract 12 bits from MSB
    crc = (crc >> 4) & 0xFFF

    if ref_out:
        crc = _reflect12(crc)

    return (crc ^ xor_out) & 0xFFF


def _reflect8(value: int) -> int:
    """Reflect 8 bits."""
    result = 0
    for i in range(8):
        result = (result << 1) | ((value >> i) & 1)
    return result


def _reflect12(value: int) -> int:
    """Reflect 12 bits."""
    result = 0
    for i in range(12):
        result = (result << 1) | ((value >> i) & 1)
    return result


# ============ Standard CRC-12 variants ============


def crc12_umts(data: bytes) -> int:
    """CRC-12/UMTS.

    poly=0x80F init=0x000 refin=false refout=false xorout=0x000
    Used in UMTS/3G telecommunications.
    """
    return crc12(data, poly=0x80F, init=0x000, ref_in=False, ref_out=False,
                 xor_out=0x000)


def crc12_cdma2000(data: bytes) -> int:
    """CRC-12/CDMA2000.

    poly=0xF13 init=0xFFF refin=false refout=false xorout=0x000
    Used in CDMA2000 telecommunications.
    """
    return crc12(data, poly=0xF13, init=0xFFF, ref_in=False, ref_out=False,
                 xor_out=0x000)


def crc12_dect(data: bytes) -> int:
    """CRC-12/DECT (Digital Enhanced Cordless Telecommunications).

    poly=0x80F init=0x000 refin=false refout=false xorout=0x000
    Used in DECT cordless phones.
    """
    return crc12(data, poly=0x80F, init=0x000, ref_in=False, ref_out=False,
                 xor_out=0x000)


def crc12_gsm(data: bytes) -> int:
    """CRC-12/GSM.

    poly=0xD31 init=0x000 refin=false refout=false xorout=0xFFF
    Used in GSM telecommunications.
    """
    return crc12(data, poly=0xD31, init=0x000, ref_in=False, ref_out=False,
                 xor_out=0xFFF)
