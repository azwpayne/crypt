# @author  : azwpayne(https://github.com/azwpayne)
# @name    : DES.py
# @time    : 2026/3/15 12:00 Sun
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : DES block cipher implementation with Feistel network

"""
DES (Data Encryption Standard) Block Cipher Implementation.

This module implements the DES algorithm with:
- Feistel network with 16 rounds
- Initial Permutation (IP) and Final Permutation (FP)
- Expansion permutation (E)
- S-box substitution
- P-permutation
- Key schedule with PC-1 and PC-2
- CBC mode with PKCS7 padding

DES uses a 56-bit key (64 bits with parity) and operates on 64-bit blocks.
"""

from __future__ import annotations

# Initial Permutation Table (IP) - 64 bits to 64 bits
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Final Permutation Table (FP) - inverse of IP
FP_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

# Expansion Permutation Table (E) - 32 bits to 48 bits
E_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

# P-Permutation Table - 32 bits to 32 bits
P_TABLE = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]

# S-Boxes (8 S-boxes, each 6 bits to 4 bits)
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

# Permuted Choice 1 (PC-1) - 64 bits to 56 bits (removes parity bits)
PC1_TABLE = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

# Permuted Choice 2 (PC-2) - 56 bits to 48 bits
PC2_TABLE = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Left shift schedule for key generation
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def _permute(block: int, table: list[int], input_bits: int) -> int:
    """Apply a permutation table to a block of bits."""
    result = 0
    for i, bit_pos in enumerate(table):
        # bit_pos is 1-indexed in DES tables
        bit = (block >> (input_bits - bit_pos)) & 1
        result |= bit << (len(table) - 1 - i)
    return result


def _left_rotate(value: int, bits: int, size: int) -> int:
    """Left rotate a value by specified bits."""
    mask = (1 << size) - 1
    return ((value << bits) | (value >> (size - bits))) & mask


def _generate_subkeys(key: int) -> list[int]:
    """Generate 16 subkeys from the main key."""
    # Apply PC-1 to get 56-bit key
    key_56 = _permute(key, PC1_TABLE, 64)

    # Split into left and right halves (28 bits each)
    left = (key_56 >> 28) & 0xFFFFFFF
    right = key_56 & 0xFFFFFFF

    subkeys = []
    for shift in SHIFT_SCHEDULE:
        # Rotate both halves
        left = _left_rotate(left, shift, 28)
        right = _left_rotate(right, shift, 28)

        # Combine and apply PC-2 to get 48-bit subkey
        combined = (left << 28) | right
        subkey = _permute(combined, PC2_TABLE, 56)
        subkeys.append(subkey)

    return subkeys


def _s_box_substitution(block: int) -> int:
    """Apply S-box substitution to a 48-bit block, producing 32 bits."""
    result = 0
    for i in range(8):
        # Extract 6-bit chunk
        chunk = (block >> (42 - i * 6)) & 0x3F

        # Get row (bits 0 and 5) and column (bits 1-4)
        row = ((chunk >> 5) & 1) | ((chunk & 1) << 1)
        col = (chunk >> 1) & 0xF

        # S-box lookup
        s_value = S_BOXES[i][row][col]
        result |= s_value << (28 - i * 4)

    return result


def _feistel_function(right: int, subkey: int) -> int:
    """
    The Feistel (F) function.
    Expands 32 bits to 48, XORs with subkey, S-box substitution, P-permutation.
    """
    # Expansion: 32 bits -> 48 bits
    expanded = _permute(right, E_TABLE, 32)

    # XOR with subkey
    xored = expanded ^ subkey

    # S-box substitution: 48 bits -> 32 bits
    substituted = _s_box_substitution(xored)

    # P-permutation: 32 bits -> 32 bits
    permuted = _permute(substituted, P_TABLE, 32)

    return permuted


def _des_block_encrypt(block: int, subkeys: list[int]) -> int:
    """Encrypt a single 64-bit block using DES."""
    # Initial Permutation
    block = _permute(block, IP_TABLE, 64)

    # Split into left and right halves (32 bits each)
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF

    # 16 rounds of Feistel network
    for i in range(16):
        # Save current right
        new_right = left ^ _feistel_function(right, subkeys[i])
        left = right
        right = new_right

    # Final swap (undo the last swap)
    block = (right << 32) | left

    # Final Permutation
    return _permute(block, FP_TABLE, 64)


def _des_block_decrypt(block: int, subkeys: list[int]) -> int:
    """Decrypt a single 64-bit block using DES."""
    # Initial Permutation
    block = _permute(block, IP_TABLE, 64)

    # Split into left and right halves
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF

    # 16 rounds of Feistel network (with subkeys in reverse order)
    for i in range(15, -1, -1):
        new_right = left ^ _feistel_function(right, subkeys[i])
        left = right
        right = new_right

    # Final swap
    block = (right << 32) | left

    # Final Permutation
    return _permute(block, FP_TABLE, 64)


def _bytes_to_int(data: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(data, 'big')


def _int_to_bytes(value: int, length: int) -> bytes:
    """Convert integer to bytes (big-endian)."""
    return value.to_bytes(length, 'big')


def _pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """Apply PKCS7 padding."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    if not data:
        return data
    padding_len = data[-1]
    if padding_len > len(data) or padding_len == 0:
        return data
    # Verify padding
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            return data
    return data[:-padding_len]


class DES:
    """
    DES (Data Encryption Standard) block cipher.

    Uses a 64-bit key (8 bytes, where every 8th bit is a parity bit).
    Operates on 64-bit blocks (8 bytes).

    Supports ECB and CBC modes with PKCS7 padding.
    """

    BLOCK_SIZE = 8  # 64 bits

    def __init__(self, key: bytes) -> None:
        """
        Initialize DES cipher with a key.

        Args:
            key: 8-byte key (64 bits, parity bits ignored)

        Raises:
            ValueError: If key is not 8 bytes
        """
        if len(key) != 8:
            raise ValueError(f"Key must be 8 bytes, got {len(key)}")

        self.key = key
        self.key_int = _bytes_to_int(key)
        self.subkeys = _generate_subkeys(self.key_int)

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using ECB mode.

        Args:
            plaintext: Data to encrypt (will be padded to 8-byte blocks)

        Returns:
            Encrypted ciphertext
        """
        # Pad the plaintext
        padded = _pkcs7_pad(plaintext, self.BLOCK_SIZE)

        ciphertext = bytearray()
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            block_int = _bytes_to_int(block)
            encrypted_int = _des_block_encrypt(block_int, self.subkeys)
            ciphertext.extend(_int_to_bytes(encrypted_int, self.BLOCK_SIZE))

        return bytes(ciphertext)

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using ECB mode.

        Args:
            ciphertext: Data to decrypt (must be multiple of 8 bytes)

        Returns:
            Decrypted plaintext (padding removed)
        """
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError(f"Ciphertext must be multiple of {self.BLOCK_SIZE} bytes")

        plaintext = bytearray()
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            block_int = _bytes_to_int(block)
            decrypted_int = _des_block_decrypt(block_int, self.subkeys)
            plaintext.extend(_int_to_bytes(decrypted_int, self.BLOCK_SIZE))

        # Remove padding
        return _pkcs7_unpad(bytes(plaintext))

    def encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        """
        Encrypt data using CBC mode.

        Args:
            plaintext: Data to encrypt
            iv: 8-byte initialization vector

        Returns:
            Encrypted ciphertext
        """
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError(f"IV must be {self.BLOCK_SIZE} bytes")

        # Pad the plaintext
        padded = _pkcs7_pad(plaintext, self.BLOCK_SIZE)

        ciphertext = bytearray()
        prev_block = _bytes_to_int(iv)

        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            block_int = _bytes_to_int(block)

            # XOR with previous ciphertext block (or IV)
            xored = block_int ^ prev_block

            # Encrypt
            encrypted_int = _des_block_encrypt(xored, self.subkeys)
            ciphertext.extend(_int_to_bytes(encrypted_int, self.BLOCK_SIZE))

            # Update previous block
            prev_block = encrypted_int

        return bytes(ciphertext)

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt data using CBC mode.

        Args:
            ciphertext: Data to decrypt (must be multiple of 8 bytes)
            iv: 8-byte initialization vector

        Returns:
            Decrypted plaintext (padding removed)
        """
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError(f"IV must be {self.BLOCK_SIZE} bytes")
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError(f"Ciphertext must be multiple of {self.BLOCK_SIZE} bytes")

        plaintext = bytearray()
        prev_block = _bytes_to_int(iv)

        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            block_int = _bytes_to_int(block)

            # Decrypt
            decrypted_int = _des_block_decrypt(block_int, self.subkeys)

            # XOR with previous ciphertext block (or IV)
            xored = decrypted_int ^ prev_block
            plaintext.extend(_int_to_bytes(xored, self.BLOCK_SIZE))

            # Update previous block
            prev_block = block_int

        # Remove padding
        return _pkcs7_unpad(bytes(plaintext))


def des_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
    """
    Convenience function for DES encryption.

    Args:
        plaintext: Data to encrypt
        key: 8-byte key
        iv: Optional 8-byte IV for CBC mode (if None, ECB is used)

    Returns:
        Encrypted ciphertext
    """
    des = DES(key)
    if iv is None:
        return des.encrypt_ecb(plaintext)
    return des.encrypt_cbc(plaintext, iv)


def des_decrypt(ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
    """
    Convenience function for DES decryption.

    Args:
        ciphertext: Data to decrypt
        key: 8-byte key
        iv: Optional 8-byte IV for CBC mode (if None, ECB is used)

    Returns:
        Decrypted plaintext
    """
    des = DES(key)
    if iv is None:
        return des.decrypt_ecb(ciphertext)
    return des.decrypt_cbc(ciphertext, iv)


if __name__ == "__main__":
    # Test vectors
    key = b"12345678"
    iv = b"00000000"
    plaintext = b"hello wo"  # Exactly 8 bytes for testing

    des = DES(key)

    # ECB mode test
    encrypted = des.encrypt_ecb(plaintext)
    decrypted = des.decrypt_ecb(encrypted)
    print(f"ECB: {plaintext!r} -> {encrypted.hex()} -> {decrypted!r}")

    # CBC mode test
    encrypted = des.encrypt_cbc(plaintext, iv)
    decrypted = des.decrypt_cbc(encrypted, iv)
    print(f"CBC: {plaintext!r} -> {encrypted.hex()} -> {decrypted!r}")

    # Longer plaintext test
    plaintext2 = b"hello world!!!!!"
    encrypted2 = des.encrypt_cbc(plaintext2, iv)
    decrypted2 = des.decrypt_cbc(encrypted2, iv)
    print(f"CBC long: {plaintext2!r} -> {encrypted2.hex()} -> {decrypted2!r}")
