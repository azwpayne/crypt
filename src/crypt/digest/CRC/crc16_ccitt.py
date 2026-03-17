"""CRC-16-CCITT implementation.

CRC-16-CCITT uses polynomial 0x1021.
Common variants:
- CRC-16-CCITT-FALSE (init=0xFFFF)
- CRC-16-CCITT-TRUE (init=0x1D0F)
- CRC-16-CCITT-XMODEM (init=0x0000)
- CRC-16-CCITT-Kermit (init=0x0000, ref_in/ref_out=true)
"""


def crc16_ccitt(
        data: bytes,
        init: int = 0xFFFF,
        *,
        ref_in: bool = False,
        ref_out: bool = False,
        xor_out: int = 0x0000,
) -> int:
    """Generic CRC-16-CCITT calculation function.

    Uses polynomial 0x1021.

    Args:
        data: Input byte data
        init: Initial value (0xFFFF for FALSE, 0x1D0F for TRUE, 0x0000 for XMODEM)
        ref_in: Whether to reverse input bits
        ref_out: Whether to reverse output bits
        xor_out: Final XOR value

    Returns:
        CRC-16-CCITT checksum (0-65535)
    """
    poly = 0x1021

    # Generate CRC lookup table
    crc_table = [0] * 256
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
        crc_table[i] = crc

    # Initialize CRC value
    crc = init

    # Process each byte
    for byte in data:
        if ref_in:
            byte = _reverse_bits8(byte)

        crc = crc_table[(crc >> 8) ^ byte] ^ ((crc << 8) & 0xFFFF)
        crc &= 0xFFFF

    # Output processing
    if ref_out:
        crc = _reverse_bits16(crc)

    return (crc ^ xor_out) & 0xFFFF


def _reverse_bits8(byte: int) -> int:
    """Reverse 8 bits."""
    result = 0
    for i in range(8):
        result = (result << 1) | ((byte >> i) & 1)
    return result


def _reverse_bits16(value: int) -> int:
    """Reverse 16 bits."""
    result = 0
    for i in range(16):
        result = (result << 1) | ((value >> i) & 1)
    return result


# ============ Standard CRC-16-CCITT variants ============


def crc16_ccitt_false(data: bytes) -> int:
    """CRC-16-CCITT-FALSE.

    poly=0x1021 init=0xFFFF refin=false refout=false xorout=0x0000
    Most common CCITT variant.
    """
    return crc16_ccitt(data, init=0xFFFF, ref_in=False, ref_out=False, xor_out=0x0000)


def crc16_ccitt_true(data: bytes) -> int:
    """CRC-16-CCITT-TRUE (also known as CRC-16-CCITT-AUG).

    poly=0x1021 init=0x1D0F refin=false refout=false xorout=0x0000
    Initial value accounts for augmented data.
    """
    return crc16_ccitt(data, init=0x1D0F, ref_in=False, ref_out=False, xor_out=0x0000)


def crc16_ccitt_xmodem(data: bytes) -> int:
    """CRC-16-CCITT-XMODEM.

    poly=0x1021 init=0x0000 refin=false refout=false xorout=0x0000
    Used in XMODEM file transfer.
    """
    return crc16_ccitt(data, init=0x0000, ref_in=False, ref_out=False, xor_out=0x0000)


def crc16_ccitt_kermit(data: bytes) -> int:
    """CRC-16-CCITT-Kermit (also known as CRC-16/CCITT).

    poly=0x1021 init=0x0000 refin=true refout=true xorout=0x0000
    Used in Kermit file transfer protocol.
    """
    return crc16_ccitt(data, init=0x0000, ref_in=True, ref_out=True, xor_out=0x0000)


def crc16_ccitt_1d0f(data: bytes) -> int:
    """CRC-16-CCITT with init 0x1D0F (alias for TRUE variant).

    poly=0x1021 init=0x1D0F refin=false refout=false xorout=0x0000
    """
    return crc16_ccitt_true(data)


def crc16_ccitt_ffff(data: bytes) -> int:
    """CRC-16-CCITT with init 0xFFFF (alias for FALSE variant).

    poly=0x1021 init=0xFFFF refin=false refout=false xorout=0x0000
    """
    return crc16_ccitt_false(data)
