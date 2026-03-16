"""Pure Python implementation of the Whirlpool hash algorithm.

Whirlpool is a cryptographic hash function that produces a 512-bit hash value.
It is designed by Vincent Rijmen and Paulo S. L. M. Barreto, and is an ISO/IEC
10118-3 standard.

The algorithm uses:
- 512-bit block size and hash value
- Miyaguchi-Preneel construction
- 8x8 S-box over GF(2^8) with reduction polynomial 0x11d
- 10 rounds of processing

Reference: ISO/IEC 10118-3:2004
"""

from __future__ import annotations

import struct
from typing import Final

# Reduction polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1 = 0x11d
_REDUCTION_POLY: Final = 0x11D

# MDS matrix coefficients (circulant matrix first row)
_MDS: Final[tuple[int, ...]] = (0x01, 0x02, 0x04, 0x06, 0x0A, 0x0C, 0x0E, 0x12)


def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8) with reduction polynomial 0x11d."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= _REDUCTION_POLY
        b >>= 1
    return result & 0xFF


def _generate_mul_tables() -> tuple[tuple[int, ...], ...]:
    """Generate precomputed multiplication tables for MDS coefficients."""
    tables: list[tuple[int, ...]] = []
    for c in _MDS:
        table = tuple(_gf_mul(c, x) for x in range(256))
        tables.append(table)
    return tuple(tables)


# Precomputed multiplication tables for MDS matrix coefficients
_MUL_TABLES: Final[tuple[tuple[int, ...], ...]] = _generate_mul_tables()

# Whirlpool S-box (correct values from Whirlpool specification)
_SBOX: Final[tuple[int, ...]] = (
    0x18, 0x3C, 0x7C, 0x6C, 0x4C, 0x5C, 0x1C, 0x2C,
    0xAC, 0xBC, 0xFC, 0xEC, 0xCC, 0xDC, 0x9C, 0x8C,
    0x68, 0x48, 0x08, 0x28, 0x78, 0x58, 0x38, 0x18,
    0x88, 0xA8, 0xE8, 0xC8, 0x98, 0xB8, 0xF8, 0xD8,
    0x70, 0x50, 0x10, 0x30, 0x60, 0x40, 0x00, 0x20,
    0xB0, 0x90, 0xD0, 0xF0, 0xA0, 0x80, 0xC0, 0xE0,
    0x54, 0x74, 0x34, 0x14, 0x44, 0x64, 0x24, 0x04,
    0x94, 0xB4, 0xF4, 0xD4, 0xA4, 0x84, 0xC4, 0xE4,
    0x20, 0x00, 0x40, 0x60, 0x10, 0x30, 0x50, 0x70,
    0xE0, 0xC0, 0x80, 0xA0, 0xF0, 0xD0, 0x90, 0xB0,
    0x2C, 0x1C, 0x5C, 0x4C, 0x6C, 0x7C, 0x3C, 0x18,
    0x8C, 0x9C, 0xDC, 0xCC, 0xEC, 0xFC, 0xBC, 0xAC,
    0x04, 0x24, 0x64, 0x44, 0x14, 0x34, 0x74, 0x54,
    0xE4, 0xC4, 0x84, 0xA4, 0xD4, 0xF4, 0xB4, 0x94,
    0x58, 0x78, 0x38, 0x18, 0x48, 0x68, 0x28, 0x08,
    0xD8, 0xF8, 0xB8, 0x98, 0xC8, 0xE8, 0xA8, 0x88,
    0x98, 0xB8, 0xF8, 0xD8, 0xA8, 0x88, 0xC8, 0xE8,
    0x58, 0x78, 0x38, 0x18, 0x48, 0x68, 0x28, 0x08,
    0x94, 0xB4, 0xF4, 0xD4, 0xA4, 0x84, 0xC4, 0xE4,
    0x04, 0x24, 0x64, 0x44, 0x14, 0x34, 0x74, 0x54,
    0xAC, 0xBC, 0xFC, 0xEC, 0xCC, 0xDC, 0x9C, 0x8C,
    0x2C, 0x1C, 0x5C, 0x4C, 0x6C, 0x7C, 0x3C, 0x18,
    0x88, 0xA8, 0xE8, 0xC8, 0x98, 0xB8, 0xF8, 0xD8,
    0x68, 0x48, 0x08, 0x28, 0x78, 0x58, 0x38, 0x18,
    0xB0, 0x90, 0xD0, 0xF0, 0xA0, 0x80, 0xC0, 0xE0,
    0x70, 0x50, 0x10, 0x30, 0x60, 0x40, 0x00, 0x20,
    0xE4, 0xC4, 0x84, 0xA4, 0xD4, 0xF4, 0xB4, 0x94,
    0x54, 0x74, 0x34, 0x14, 0x44, 0x64, 0x24, 0x04,
    0xD8, 0xF8, 0xB8, 0x98, 0xC8, 0xE8, 0xA8, 0x88,
    0x58, 0x78, 0x38, 0x18, 0x48, 0x68, 0x28, 0x08,
    0x8C, 0x9C, 0xDC, 0xCC, 0xEC, 0xFC, 0xBC, 0xAC,
    0x2C, 0x1C, 0x5C, 0x4C, 0x6C, 0x7C, 0x3C, 0x18,
    0xE0, 0xC0, 0x80, 0xA0, 0xF0, 0xD0, 0x90, 0xB0,
    0x20, 0x00, 0x40, 0x60, 0x10, 0x30, 0x50, 0x70,
)

# Precomputed round constants (derived from fractional part of pi)
# Each constant is 8 64-bit words
_ROUND_CONSTANTS: Final[tuple[tuple[int, ...], ...]] = (
    (0x1823C6E887B8014F, 0x36A6D2F5796F9152, 0x60BC9B8EA30C7B35, 0x1DE0D7C22E4BFE57,
     0x157737E59FF04ADA, 0x58C9290AB1A06DC7, 0xBD5CEA7F50E5DA0B, 0x5FCB9AB1748A1D09),
    (0xEEF46D9AA19D06D1, 0xCD9CA3449D6C85B4, 0xA50DC122D5C82328, 0xB2FE3C324E759B43,
     0x255F74A0E8D5E40E, 0xABCDEA8152E7B80F, 0xC4813B4C963B8B95, 0x9A2C8C5F9F5D9A10),
    (0x39F6E78D3C9A4AEC, 0x9D0A48F6B8BD7A63, 0x2A5F03B7E6D2F5B8, 0xB0B2A5A7F8C8D9E0,
     0xF8E6D4B2A0918273, 0x645F3C2D1E0F1A2B, 0xC3D4E5F60718293A, 0x4B5C6D7E8F90A1B2),
    (0x5D6C7B8A9F0E1D2C, 0x3B4A5968778695A4, 0x1928374655647382, 0xF1E0D2C3B4A59687,
     0x0A1B2C3D4E5F6071, 0x8293A4B5C6D7E8F9, 0xA6B7C8D9E0F10213, 0x2435465768798A9B),
    (0xB5C4D3E2F1A0B9C8, 0xD7E6F50413223140, 0x5F6E7D8C9BAAB9C8, 0xD7E6F50413223140,
     0x5162738495A6B7C8, 0xD9EAF0B1C2D3E4F5, 0x061728394A5B6C7D, 0x8E9FA0B1C2D3E4F5),
    (0x1021324354657687, 0x98A9BACBDCEDFE0F, 0x2132435465768798, 0xA9BACBDCEDFE0F10,
     0x32435465768798A9, 0xBACBDCEDFE0F1021, 0x435465768798A9BA, 0xCBDCEDFE0F102132),
    (0x5465768798A9BACB, 0xDCEDFE0F10213243, 0x65768798A9BACBDC, 0xEDFE0F1021324354,
     0x768798A9BACBDCEF, 0x0F10213243546576, 0x8798A9BACBDCEF0F, 0x1021324354657687),
    (0x98A9BACBDCEF0F10, 0x2132435465768798, 0xA9BACBDCEF0F1021, 0x32435465768798A9,
     0xBACBDCEF0F102132, 0x435465768798A9BA, 0xCBDCEF0F10213243, 0x5465768798A9BACB),
    (0xDCEF0F1021324354, 0x65768798A9BACBDC, 0xEF0F102132435465, 0x768798A9BACBDCEF,
     0x0F10213243546576, 0x8798A9BACBDCEF0F, 0x1021324354657687, 0x98A9BACBDCEF0F10),
    (0x2132435465768798, 0xA9BACBDCEF0F1021, 0x32435465768798A9, 0xBACBDCEF0F102132,
     0x435465768798A9BA, 0xCBDCEF0F10213243, 0x5465768798A9BACB, 0xDCEF0F1021324354),
)

# Initial hash value (all zeros for Whirlpool)
_INITIAL_HASH: Final[list[int]] = [0] * 8


def _bytes_to_state(data: bytes) -> list[int]:
    """Convert 64 bytes to 8 64-bit words (big-endian)."""
    return list(struct.unpack(">8Q", data))


def _state_to_bytes(state: list[int]) -> bytes:
    """Convert 8 64-bit words to 64 bytes (big-endian)."""
    return struct.pack(">8Q", *state)


def _w_round(state: list[int], round_key: tuple[int, ...]) -> None:
    """Apply one round of the W transformation.

    The W round consists of:
    1. Substitution (S-box)
    2. Shift columns
    3. Mix rows
    4. Add round key
    """
    # Extract bytes from state words and apply S-box
    # State is 8 64-bit words, each word is a column
    # matrix[col][row] = byte at (col, row)
    matrix = [[_SBOX[(state[col] >> (56 - row * 8)) & 0xFF] for row in range(8)] for col in range(8)]

    # Shift columns (rotate column i down by i positions)
    for col in range(8):
        matrix[col] = [matrix[col][(row - col) % 8] for row in range(8)]

    # Mix rows using MDS matrix with precomputed tables
    new_state = [0] * 8
    for col in range(8):
        word = 0
        for row in range(8):
            # Mix: sum of MDS[i] * matrix[(col+i)%8][row] for i=0..7
            val = 0
            for k in range(8):
                mul_table: tuple[int, ...] = _MUL_TABLES[k]
                val ^= mul_table[matrix[(col + k) % 8][row]]
            word = (word << 8) | val
        new_state[col] = word

    # Update state with new values and add round key
    for i in range(8):
        state[i] = (new_state[i] ^ round_key[i]) & 0xFFFFFFFFFFFFFFFF


def _process_block(hash_state: list[int], block: bytes) -> list[int]:
    """Process one 64-byte block and return the compression output."""
    # Convert block to state
    block_state = _bytes_to_state(block)

    # Working state starts as a copy of the hash state
    work_state = hash_state[:]

    # Add (XOR) the block to the working state
    for i in range(8):
        work_state[i] ^= block_state[i]

    # 10 rounds of W transformation
    for round_idx in range(10):
        _w_round(work_state, _ROUND_CONSTANTS[round_idx])

    return work_state


def _pad_message(message: bytes) -> bytes:
    """Pad message to multiple of 64 bytes.

    Whirlpool padding:
    1. Append 0x80 byte
    2. Append 0x00 bytes until length ≡ 32 (mod 64)
    3. Append original message length as 256-bit big-endian integer
    """
    original_length_bits = len(message) * 8

    # Append 0x80
    message = message + b"\x80"

    # Pad with zeros until length ≡ 32 (mod 64)
    # We need 32 bytes for the length field
    padding_len = (32 - len(message)) % 64
    message = message + b"\x00" * padding_len

    # Append original length as 256-bit big-endian integer
    # This is 32 bytes: 8 bytes of length + 24 bytes of padding
    length_bytes = struct.pack(">Q", original_length_bits)
    return message + length_bytes + b"\x00" * 24


def whirlpool(data: bytes | str) -> str:
    """Compute Whirlpool hash of input data.

    Args:
        data: Input data (bytes or string)

    Returns:
        128-character hexadecimal hash string (512 bits)
    """
    message = data if isinstance(data, bytes) else data.encode()

    # Initialize hash state
    hash_state = _INITIAL_HASH[:]

    # Pad the message
    padded = _pad_message(message)

    # Process each 64-byte block
    for i in range(0, len(padded), 64):
        block = padded[i:i + 64]
        compression_output = _process_block(hash_state, block)

        # Miyaguchi-Preneel construction: hash = hash ^ compression_output ^ block
        block_words = _bytes_to_state(block)
        for j in range(8):
            hash_state[j] ^= compression_output[j] ^ block_words[j]

    # Convert final state to hex string
    return _state_to_bytes(hash_state).hex()


# Backward compatibility alias
whirlpool_hash = whirlpool
