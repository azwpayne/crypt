"""Pure Python implementation of Serpent block cipher.

Serpent is a 128-bit block cipher with 32 rounds, designed as an AES candidate.
It uses a Substitution-Permutation Network (SPN) structure with 8 S-boxes.

This implementation is for educational purposes only.
"""

from __future__ import annotations

from typing import Final

# Serpent S-boxes (4-bit to 4-bit, applied in parallel to 32-bit words)
SBOXES: Final[tuple[tuple[int, ...], ...]] = (
    (3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12),
    (15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4),
    (8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2),
    (0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14),
    (1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13),
    (15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1),
    (7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0),
    (1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6),
)

# Inverse S-boxes
INV_SBOXES: Final[tuple[tuple[int, ...], ...]] = (
    (13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2),
    (5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0),
    (12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7),
    (0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1),
    (5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1),
    (8, 15, 2, 9, 4, 1, 13, 14, 11, 7, 5, 3, 7, 12, 10, 0),
    (15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11),
    (3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2),
)

# Initial permutation (IP)
IP_TABLE: Final[tuple[int, ...]] = (
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
)

# Final permutation (FP)
FP_TABLE: Final[tuple[int, ...]] = (
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
)


def _permute(block: int, table: tuple[int, ...]) -> int:
    """Apply a permutation to a 128-bit block."""
    result = 0
    for i, bit_pos in enumerate(table):
        bit = (block >> bit_pos) & 1
        result |= bit << i
    return result


def _apply_sbox(word: int, sbox: tuple[int, ...]) -> int:
    """Apply 4-bit S-box to 32-bit word (8 parallel applications)."""
    result = 0
    for i in range(8):
        nibble = (word >> (4 * i)) & 0xF
        result |= sbox[nibble] << (4 * i)
    return result


def _linear_transform(words: list[int]) -> list[int]:
    """Apply linear transformation to 4 32-bit words."""
    x0, x1, x2, x3 = words
    x0 = ((x0 << 13) | (x0 >> 19)) & 0xFFFFFFFF
    x2 = ((x2 << 3) | (x2 >> 29)) & 0xFFFFFFFF
    x1 = x1 ^ x0 ^ x2
    x3 = x3 ^ x2 ^ ((x0 << 3) & 0xFFFFFFFF)
    x1 = ((x1 << 1) | (x1 >> 31)) & 0xFFFFFFFF
    x3 = ((x3 << 7) | (x3 >> 25)) & 0xFFFFFFFF
    x0 = x0 ^ x1 ^ x3
    x2 = x2 ^ x3 ^ ((x1 << 7) & 0xFFFFFFFF)
    x0 = ((x0 << 5) | (x0 >> 27)) & 0xFFFFFFFF
    x2 = ((x2 << 22) | (x2 >> 10)) & 0xFFFFFFFF
    return [x0, x1, x2, x3]


def _inv_linear_transform(words: list[int]) -> list[int]:
    """Apply inverse linear transformation."""
    x0, x1, x2, x3 = words
    x2 = ((x2 >> 22) | (x2 << 10)) & 0xFFFFFFFF
    x0 = ((x0 >> 5) | (x0 << 27)) & 0xFFFFFFFF
    x2 = x2 ^ x3 ^ ((x1 << 7) & 0xFFFFFFFF)
    x0 = x0 ^ x1 ^ x3
    x3 = ((x3 >> 7) | (x3 << 25)) & 0xFFFFFFFF
    x1 = ((x1 >> 1) | (x1 << 31)) & 0xFFFFFFFF
    x3 = x3 ^ x2 ^ ((x0 << 3) & 0xFFFFFFFF)
    x1 = x1 ^ x0 ^ x2
    x2 = ((x2 >> 3) | (x2 << 29)) & 0xFFFFFFFF
    x0 = ((x0 >> 13) | (x0 << 19)) & 0xFFFFFFFF
    return [x0, x1, x2, x3]


def key_schedule(key: bytes) -> list[list[int]]:
    """Generate 33 round keys (132 32-bit words) from key."""
    # Expand key to 256 bits
    key_len = len(key)
    if key_len == 0:
        raise ValueError("Key cannot be empty")

    # Pad key to 256 bits
    padded_key = bytearray(32)
    for i in range(32):
        if i < key_len:
            padded_key[i] = key[i]
        elif i == key_len:
            padded_key[i] = 0x80
        else:
            padded_key[i] = 0x00

    # Convert to 8 32-bit words (little endian)
    k = [int.from_bytes(padded_key[i:i+4], 'little') for i in range(0, 32, 4)]

    # Prekeys
    prekeys = []
    for i in range(8):
        prekeys.append(k[i])

    # Generate remaining prekeys
    for i in range(8, 140):
        prekeys.append(
            ((prekeys[i-8] ^ prekeys[i-5] ^ prekeys[i-3] ^ prekeys[i-1] ^
              (0x9E3779B9 ^ i)) << 11) & 0xFFFFFFFF |
            ((prekeys[i-8] ^ prekeys[i-5] ^ prekeys[i-3] ^ prekeys[i-1] ^
              (0x9E3779B9 ^ i)) >> 21)
        )

    # Generate round keys
    round_keys = []
    for i in range(33):
        sbox_idx = (32 + 3 - i) % 8
        round_key = []
        for j in range(4):
            word = prekeys[4*i + j]
            round_key.append(_apply_sbox(word, SBOXES[sbox_idx]))
        round_keys.append(round_key)

    return round_keys


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt single 16-byte block."""
    if len(block) != 16:
        raise ValueError(f"Block must be 16 bytes, got {len(block)}")

    round_keys = key_schedule(key)

    # Convert block to 128-bit integer
    block_int = int.from_bytes(block, 'little')

    # Initial permutation
    block_int = _permute(block_int, IP_TABLE)

    # Split into 4 32-bit words
    words = [
        block_int & 0xFFFFFFFF,
        (block_int >> 32) & 0xFFFFFFFF,
        (block_int >> 64) & 0xFFFFFFFF,
        (block_int >> 96) & 0xFFFFFFFF,
    ]

    # 32 rounds
    for i in range(32):
        # XOR with round key
        words = [words[j] ^ round_keys[i][j] for j in range(4)]

        # Apply S-box
        sbox_idx = i % 8
        words = [_apply_sbox(w, SBOXES[sbox_idx]) for w in words]

        # Linear transform (except last round)
        if i < 31:
            words = _linear_transform(words)

    # Final XOR with round key 32
    words = [words[j] ^ round_keys[32][j] for j in range(4)]

    # Combine words
    result = (words[0] | (words[1] << 32) |
              (words[2] << 64) | (words[3] << 96))

    # Final permutation
    result = _permute(result, FP_TABLE)

    return result.to_bytes(16, 'little')


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt single 16-byte block."""
    if len(block) != 16:
        raise ValueError(f"Block must be 16 bytes, got {len(block)}")

    round_keys = key_schedule(key)

    # Convert block to 128-bit integer
    block_int = int.from_bytes(block, 'little')

    # Initial permutation (FP is its own inverse)
    block_int = _permute(block_int, FP_TABLE)

    # Split into 4 32-bit words
    words = [
        block_int & 0xFFFFFFFF,
        (block_int >> 32) & 0xFFFFFFFF,
        (block_int >> 64) & 0xFFFFFFFF,
        (block_int >> 96) & 0xFFFFFFFF,
    ]

    # XOR with round key 32
    words = [words[j] ^ round_keys[32][j] for j in range(4)]

    # 32 rounds in reverse
    for i in range(31, -1, -1):
        # Inverse linear transform (except first iteration)
        if i < 31:
            words = _inv_linear_transform(words)

        # Apply inverse S-box
        sbox_idx = i % 8
        words = [_apply_sbox(w, INV_SBOXES[sbox_idx]) for w in words]

        # XOR with round key
        words = [words[j] ^ round_keys[i][j] for j in range(4)]

    # Combine words
    result = (words[0] | (words[1] << 32) |
              (words[2] << 64) | (words[3] << 96))

    # Final permutation
    result = _permute(result, IP_TABLE)

    return result.to_bytes(16, 'little')


# PKCS7 padding helpers
def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Pad data using PKCS7."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    if not data:
        return data
    padding_len = data[-1]
    if padding_len > len(data):
        return data
    return data[:-padding_len]


def serpent_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using Serpent in ECB mode."""
    padded = _pkcs7_pad(data, 16)
    result = b""
    for i in range(0, len(padded), 16):
        result += encrypt_block(padded[i:i+16], key)
    return result


def serpent_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt data using Serpent in ECB mode."""
    result = b""
    for i in range(0, len(data), 16):
        result += decrypt_block(data[i:i+16], key)
    return _pkcs7_unpad(result)


def serpent_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using Serpent in CBC mode."""
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    padded = _pkcs7_pad(data, 16)
    result = b""
    prev = iv

    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        encrypted = encrypt_block(xored, key)
        result += encrypted
        prev = encrypted

    return result


def serpent_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using Serpent in CBC mode."""
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    result = b""
    prev = iv

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted = decrypt_block(block, key)
        xored = bytes(a ^ b for a, b in zip(decrypted, prev))
        result += xored
        prev = block

    return _pkcs7_unpad(result)
