# @author  : azwpayne(https://github.com/azwpayne)
# @name    : twofish.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Twofish block cipher implementation (AES finalist)

"""
Twofish Block Cipher Implementation

Twofish is a 128-bit block cipher with:
- 128-bit block size
- Variable key length: 128/192/256 bits
- 16 rounds of encryption
- Key-dependent S-boxes
- MDS matrix and RS matrix for diffusion

Reference: https://www.schneier.com/academic/archives/1998/09/the_twofish_encrypti.html
"""

import struct
from typing import Union


# Twofish uses key-dependent S-boxes derived from two fixed 8x8-bit S-boxes
# These are the q0 and q1 permutations used to generate the S-boxes
Q0 = [
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
]

Q1 = [
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91,
]

# MDS matrix for diffusion (GF(2^8) multiplication)
# Each row is used to compute one byte of the output
MDS_MATRIX = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
]

# RS matrix for key schedule (GF(2^8) multiplication)
# Used to generate the S-box key material
RS_MATRIX = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
]

# Primitive polynomial for GF(2^8): x^8 + x^6 + x^3 + x^2 + 1 = 0x14D
GF_POLY = 0x14D


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with primitive polynomial 0x14D."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= GF_POLY
        b >>= 1
    return result & 0xFF


def _q_permutation(x: int, q_table: list[int]) -> int:
    """Apply q permutation (q0 or q1).

    The q permutation uses a 4-bit substitution structure.
    """
    a0 = (x >> 4) & 0xF
    b0 = x & 0xF
    a1 = a0 ^ b0
    b1 = (a0 ^ ((b0 << 3) | (b0 >> 1)) ^ (a0 << 3)) & 0xF
    a2 = Q0[16 + a1] ^ Q1[16 + b1]
    b2 = Q0[a1] ^ Q1[b1]
    a3 = a2 ^ b2
    b3 = (a2 ^ ((b2 << 3) | (b2 >> 1)) ^ (a2 << 3)) & 0xF
    a4 = Q0[16 + a3] ^ Q1[16 + b3]
    b4 = Q0[a3] ^ Q1[b3]
    return (b4 << 4) | a4


def _sbox(i: int, x: int, s_key: list[int]) -> int:
    """Compute S-box value for byte x in position i.

    Args:
        i: S-box index (0-3)
        x: Input byte
        s_key: S-box key material

    Returns:
        S-box output byte
    """
    if i == 0:
        return _q_permutation(x, Q0) ^ s_key[0]
    if i == 1:
        return _q_permutation(x, Q1) ^ s_key[1]
    if i == 2:
        return _q_permutation(x, Q1) ^ s_key[2]
    return _q_permutation(x, Q0) ^ s_key[3]


def _mds_multiply(y: list[int]) -> int:
    """Multiply vector by MDS matrix.

    Args:
        y: 4-byte input vector

    Returns:
        32-bit output word
    """
    result = 0
    for i in range(4):
        byte_val = 0
        for j in range(4):
            byte_val ^= _gf_mul(MDS_MATRIX[i][j], y[j])
        result |= byte_val << (8 * i)
    return result


def _g_function(x: int, s_key: list[int]) -> int:
    """Twofish g-function.

    The g-function applies S-boxes followed by MDS matrix multiplication.

    Args:
        x: 32-bit input
        s_key: S-box key material (4 bytes)

    Returns:
        32-bit output
    """
    y = [_sbox(i, (x >> (8 * i)) & 0xFF, s_key) for i in range(4)]
    return _mds_multiply(y)


def _rs_multiply(key_bytes: list[int]) -> int:
    """Multiply vector by RS matrix to generate S-box key.

    Args:
        key_bytes: 8-byte input vector

    Returns:
        32-bit S-box key word
    """
    result = 0
    for i in range(4):
        byte_val = 0
        for j in range(8):
            byte_val ^= _gf_mul(RS_MATRIX[i][j], key_bytes[j])
        result |= byte_val << (8 * i)
    return result


def _bytes_to_word(data: bytes) -> int:
    """Convert 4 bytes to a 32-bit word (little-endian)."""
    return struct.unpack("<I", data)[0]


def _word_to_bytes(word: int) -> bytes:
    """Convert a 32-bit word to 4 bytes (little-endian)."""
    return struct.pack("<I", word & 0xFFFFFFFF)


def _ror(x: int, n: int) -> int:
    """Rotate right a 32-bit word by n bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _rol(x: int, n: int) -> int:
    """Rotate left a 32-bit word by n bits."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


class Twofish:
    """Twofish block cipher implementation.

    Twofish is a 128-bit block cipher with 16 rounds and variable
    key length (128/192/256 bits).

    Attributes:
        key_words: The expanded key schedule (40 words)
        s_key: S-box key material (derived from the key)
        key_bits: Key length in bits (128, 192, or 256)
    """

    def __init__(self, key: bytes) -> None:
        """Initialize Twofish with a key.

        Args:
            key: The encryption key (16, 24, or 32 bytes)

        Raises:
            ValueError: If key length is invalid
        """
        key_len = len(key)
        if key_len not in (16, 24, 32):
            raise ValueError(f"Key must be 16, 24, or 32 bytes, got {key_len}")

        self.key_bits = key_len * 8
        self.key_words = [0] * 40

        # Generate S-box key material using RS matrix
        k = key_len // 8  # Number of 8-byte key blocks
        self.s_key = [0] * 4

        for i in range(k):
            key_block = list(key[i * 8:(i + 1) * 8])
            self.s_key[i] = _rs_multiply(key_block)

        # Generate key schedule
        # Split key into even and odd 32-bit words
        me = []
        mo = []
        for i in range(0, key_len, 8):
            me.append(_bytes_to_word(key[i:i + 4]))
            mo.append(_bytes_to_word(key[i + 4:i + 8]))

        rho = 0x01010101  # Rho constant

        for i in range(20):
            # Compute A and B for this round key pair
            a = _g_function(_rol(rho * (2 * i), 8), self.s_key)
            b = _g_function(_rol(rho * (2 * i + 1), 0), self.s_key)

            a = (a + me[i % k]) & 0xFFFFFFFF
            b = (b + mo[i % k]) & 0xFFFFFFFF
            b = _rol(b, 8)

            self.key_words[2 * i] = (a + b) & 0xFFFFFFFF
            self.key_words[2 * i + 1] = _rol((a + 2 * b) & 0xFFFFFFFF, 9)

    def _f_function(self, r0: int, r1: int, round_num: int) -> tuple[int, int]:
        """Twofish F-function for a round.

        Args:
            r0: First 32-bit input
            r1: Second 32-bit input
            round_num: Round number (for key whitening)

        Returns:
            Tuple of (f0, f1) outputs
        """
        # Apply g-function
        t0 = _g_function(r0, self.s_key)
        t1 = _g_function(_rol(r1, 8), self.s_key)

        # PHT (Pseudo-Hadamard Transform)
        f0 = (t0 + t1 + self.key_words[2 * round_num + 8]) & 0xFFFFFFFF
        f1 = (t0 + 2 * t1 + self.key_words[2 * round_num + 9]) & 0xFFFFFFFF

        return f0, f1

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 128-bit block.

        Args:
            block: 16-byte block to encrypt

        Returns:
            16-byte encrypted block

        Raises:
            ValueError: If block length is not 16 bytes
        """
        if len(block) != 16:
            raise ValueError(f"Block must be 16 bytes, got {len(block)}")

        # Input whitening
        r = [_bytes_to_word(block[i:i + 4]) ^ self.key_words[i // 4]
             for i in range(0, 16, 4)]

        # 16 rounds
        for round_num in range(16):
            f0, f1 = self._f_function(r[0], r[1], round_num)

            # Feistel round
            new_r2 = (_ror(r[2] ^ f0, 1))
            new_r3 = (_rol(r[3], 1) ^ f1)

            # Rotate registers for next round (swap)
            if round_num < 15:  # Don't swap after last round
                r = [new_r2, new_r3, r[0], r[1]]
            else:
                r = [r[0], r[1], new_r2, new_r3]

        # Undo the last swap and apply output whitening
        # After 16 rounds, the output order is: r[2], r[3], r[0], r[1]
        # But we need to apply whitening in reverse
        c = [0] * 4
        c[0] = r[2] ^ self.key_words[4]
        c[1] = r[3] ^ self.key_words[5]
        c[2] = r[0] ^ self.key_words[6]
        c[3] = r[1] ^ self.key_words[7]

        result = bytearray()
        for word in c:
            result.extend(_word_to_bytes(word))
        return bytes(result)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single 128-bit block.

        Args:
            block: 16-byte block to decrypt

        Returns:
            16-byte decrypted block

        Raises:
            ValueError: If block length is not 16 bytes
        """
        if len(block) != 16:
            raise ValueError(f"Block must be 16 bytes, got {len(block)}")

        # Input whitening (reverse of output whitening)
        r = [_bytes_to_word(block[i:i + 4]) ^ self.key_words[4 + i // 4]
             for i in range(0, 16, 4)]

        # Reverse the final swap
        r = [r[2], r[3], r[0], r[1]]

        # 16 rounds (in reverse)
        for round_num in range(15, -1, -1):
            f0, f1 = self._f_function(r[0], r[1], round_num)

            # Reverse Feistel round
            new_r2 = (_rol(r[2], 1) ^ f0)
            new_r3 = (_ror(r[3] ^ f1, 1))

            # Rotate registers (swap)
            if round_num > 0:
                r = [new_r2, new_r3, r[0], r[1]]
            else:
                r = [r[0], r[1], new_r2, new_r3]

        # Output whitening (reverse of input whitening)
        c = [0] * 4
        c[0] = r[2] ^ self.key_words[0]
        c[1] = r[3] ^ self.key_words[1]
        c[2] = r[0] ^ self.key_words[2]
        c[3] = r[1] ^ self.key_words[3]

        result = bytearray()
        for word in c:
            result.extend(_word_to_bytes(word))
        return bytes(result)


def _pad_pkcs7(data: bytes, block_size: int) -> bytes:
    """Apply PKCS7 padding."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def _unpad_pkcs7(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using Twofish in ECB mode.

    Args:
        key: Encryption key (16, 24, or 32 bytes)
        plaintext: Data to encrypt

    Returns:
        Encrypted data
    """
    cipher = Twofish(key)
    padded = _pad_pkcs7(plaintext, 16)

    ciphertext = bytearray()
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        ciphertext.extend(cipher.encrypt_block(block))

    return bytes(ciphertext)


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt data using Twofish in ECB mode.

    Args:
        key: Encryption key (16, 24, or 32 bytes)
        ciphertext: Data to decrypt (must be multiple of 16 bytes)

    Returns:
        Decrypted data with padding removed
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")

    cipher = Twofish(key)

    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext.extend(cipher.decrypt_block(block))

    return _unpad_pkcs7(bytes(plaintext))


def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using Twofish in CBC mode.

    Args:
        key: Encryption key (16, 24, or 32 bytes)
        iv: Initialization vector (16 bytes)
        plaintext: Data to encrypt

    Returns:
        Encrypted data
    """
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)}")

    cipher = Twofish(key)
    padded = _pad_pkcs7(plaintext, 16)

    ciphertext = bytearray()
    prev_block = iv

    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted = cipher.encrypt_block(xored)
        ciphertext.extend(encrypted)
        prev_block = encrypted

    return bytes(ciphertext)


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt data using Twofish in CBC mode.

    Args:
        key: Encryption key (16, 24, or 32 bytes)
        iv: Initialization vector (16 bytes)
        ciphertext: Data to decrypt (must be multiple of 16 bytes)

    Returns:
        Decrypted data with padding removed
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)}")

    cipher = Twofish(key)

    plaintext = bytearray()
    prev_block = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted = cipher.decrypt_block(block)
        xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
        plaintext.extend(xored)
        prev_block = block

    return _unpad_pkcs7(bytes(plaintext))
