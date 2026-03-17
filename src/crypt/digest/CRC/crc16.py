"""CRC-16 implementation.

CRC-16 is a 16-bit cyclic redundancy check.
Common variants:
- CRC-16/IBM (CRC-16-ANSI)
- CRC-16/MODBUS
- CRC-16/USB
- CRC-16/XMODEM
"""

from __future__ import annotations


def _reflect8(value: int) -> int:
    """Reflect 8 bits."""
    result = 0
    for i in range(8):
        result = (result << 1) | ((value >> i) & 1)
    return result


def _reflect16(value: int) -> int:
    """Reflect 16 bits."""
    result = 0
    for i in range(16):
        result = (result << 1) | ((value >> i) & 1)
    return result


def crc16(
        data: bytes,
        poly: int = 0x8005,
        init: int = 0x0000,
        *,
        ref_in: bool = True,
        ref_out: bool = True,
        xor_out: int = 0x0000,
) -> int:
    """Generic CRC-16 calculation function.

    Args:
        data: Input byte data
        poly: Polynomial (e.g., 0x8005 for IBM, 0x1021 for CCITT)
        init: Initial value (typically 0x0000 or 0xFFFF)
        ref_in: Whether input is reflected (LSB first)
        ref_out: Whether output is reflected
        xor_out: Final XOR value

    Returns:
        CRC-16 checksum (0-65535)
    """
    if ref_in:
        # Reflected mode (LSB first)
        # For reflected CRC, we use the reflected polynomial
        poly_ref = _reflect16(poly)

        # Generate lookup table for reflected polynomial
        crc_table = [0] * 256
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ poly_ref
                else:
                    crc >>= 1
            crc_table[i] = crc

        # Process data
        crc = init
        for byte in data:
            crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8)

        # Reflect output if needed
        if ref_out:
            crc = _reflect16(crc)
    else:
        # Non-reflected mode (MSB first)
        # Generate lookup table for normal polynomial
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

        # Process data
        crc = init
        for byte in data:
            crc = crc_table[((crc >> 8) ^ byte) & 0xFF] ^ ((crc << 8) & 0xFFFF)
            crc &= 0xFFFF

        # Reflect output if needed
        if ref_out:
            crc = _reflect16(crc)

    return (crc ^ xor_out) & 0xFFFF


# ============ Standard CRC-16 variants ============


def crc16_ibm(data: bytes) -> int:
    """CRC-16/IBM (also known as CRC-16-ANSI).

    poly=0x8005 init=0x0000 refin=true refout=false xorout=0x0000
    Used in IBM protocols and many industrial applications.

    Test vector: crc16_ibm(b"123456789") == 0xBB3D
    """
    return crc16(
        data, poly=0x8005, init=0x0000, ref_in=True, ref_out=False, xor_out=0x0000
    )


def crc16_modbus(data: bytes) -> int:
    """CRC-16/MODBUS.

    poly=0x8005 init=0xFFFF refin=true refout=false xorout=0x0000
    Used in Modbus industrial communication protocol.

    Test vector: crc16_modbus(b"123456789") == 0x4B37
    """
    return crc16(
        data, poly=0x8005, init=0xFFFF, ref_in=True, ref_out=False, xor_out=0x0000
    )


def crc16_usb(data: bytes) -> int:
    """CRC-16/USB.

    poly=0x8005 init=0xFFFF refin=true refout=false xorout=0xFFFF
    Used in USB protocol.

    Test vector: crc16_usb(b"123456789") == 0xB4C8
    """
    return crc16(
        data, poly=0x8005, init=0xFFFF, ref_in=True, ref_out=False, xor_out=0xFFFF
    )


def crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM.

    poly=0x1021 init=0x0000 refin=false refout=false xorout=0x0000
    Used in XMODEM file transfer protocol.
    Note: Same as crc16_ccitt_xmodem in crc16_ccitt module.

    Test vector: crc16_xmodem(b"123456789") == 0x31C3
    """
    return crc16(
        data, poly=0x1021, init=0x0000, ref_in=False, ref_out=False, xor_out=0x0000
    )


def crc16_ansi(data: bytes) -> int:
    """CRC-16/ANSI (alias for CRC-16/IBM).

    poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000
    """
    return crc16_ibm(data)


def crc16_dnp(data: bytes) -> int:
    """CRC-16/DNP (Distributed Network Protocol).

    poly=0x3D65 init=0x0000 refin=false refout=false xorout=0xFFFF
    Used in SCADA systems.

    Test vector: crc16_dnp(b"123456789") == 0xEA82
    """
    return crc16(
        data, poly=0x3D65, init=0x0000, ref_in=False, ref_out=False, xor_out=0xFFFF
    )
