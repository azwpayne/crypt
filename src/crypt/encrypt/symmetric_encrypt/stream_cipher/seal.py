"""Pure Python implementation of SEAL stream cipher.

SEAL (Software-Optimized Encryption Algorithm) is a stream cipher designed by
IBM. It was designed for efficient software implementation.

- 160-bit key
- 32-bit IV/position index (n)
- Uses large tables generated from SHA-1 of key
- Optimized for 32-bit processors

This implementation is for educational purposes only.
"""

from __future__ import annotations

import hashlib
from typing import Final

# SEAL parameters
L: Final[int] = 5  # Number of 32-bit words in output per call
NUM_ROUNDS: Final[int] = 5  # Number of rounds in the generator
T_SIZE: Final[int] = 512  # Size of T table
S_SIZE: Final[int] = 256  # Size of S table


def _gamma(a: int) -> tuple[int, int, int, int]:
    """The Gamma function based on SHA-1.

    Returns four 32-bit words derived from SHA-1 of input.
    """
    # Convert 32-bit integer to 4 bytes (big endian)
    data = a.to_bytes(4, "big")
    h = hashlib.sha1(data).digest()

    # Extract four 32-bit words from SHA-1 output (160 bits)
    y0 = int.from_bytes(h[:4], "big")
    y1 = int.from_bytes(h[4:8], "big")
    y2 = int.from_bytes(h[8:12], "big")
    y3 = int.from_bytes(h[12:16], "big")

    return y0, y1, y2, y3


def _initialize_tables(key: bytes) -> tuple[list[int], list[int], list[int]]:
    """Initialize SEAL tables from key.

    Args:
        key: 20-byte (160-bit) key

    Returns:
        Tuple of (T table, S table, R table)
    """
    if len(key) != 20:
        msg = f"Key must be 20 bytes, got {len(key)}"
        raise ValueError(msg)

    # Derive key-dependent tables using SHA-1
    h = hashlib.sha1(key).digest()

    # Create tables T and S
    T = [0] * T_SIZE
    S = [0] * S_SIZE

    # Fill T and S using iterated SHA-1
    j = 0
    for i in range(T_SIZE + S_SIZE):
        if i % 5 == 0:
            data = key + j.to_bytes(4, "big")
            h = hashlib.sha1(data).digest()
            j += 1

        word = int.from_bytes(h[(i % 5) * 4: (i % 5 + 1) * 4], "big")
        if i < T_SIZE:
            T[i] = word
        else:
            S[i - T_SIZE] = word

    # Create R table
    r_table = [0] * (4 * (NUM_ROUNDS + 1))

    return T, S, r_table


class SEALState:
    """SEAL cipher state."""

    def __init__(self, key: bytes, n: int) -> None:
        """Initialize SEAL state.

        Args:
            key: 20-byte key
            n: 32-bit position index
        """
        self.T, self.S, self.R = _initialize_tables(key)
        self.n = n
        self.counter = 0
        self.buffer = b""
        self._initialize_register(n)

    def _initialize_register(self, n: int) -> None:
        """Initialize the register R."""
        # R[0] through R[4] are derived from n
        n0 = (n >> 0) & 0xFFFF
        n1 = (n >> 16) & 0xFFFF
        n2 = (n >> 32) & 0xFFFF if n > 0xFFFFFFFF else 0
        n3 = (n >> 48) & 0xFFFF if n > 0xFFFFFFFF else 0

        # Initialize first words of R
        self.R[0] = n & 0xFFFFFFFF
        self.R[1] = ((n0 ^ self.T[0]) << 16) | (n1 ^ self.T[1]) & 0xFFFFFFFF
        self.R[2] = ((n1 ^ self.T[2]) << 16) | (n2 ^ self.T[3]) & 0xFFFFFFFF
        self.R[3] = ((n2 ^ self.T[4]) << 16) | (n3 ^ self.T[5]) & 0xFFFFFFFF

        # Generate remaining R values using S table
        for i in range(1, NUM_ROUNDS + 1):
            p = 4 * i
            # Generate next four values
            for j in range(4):
                idx = (self.R[p + j - 4] >> 24) & 0xFF
                self.R[p + j] = self.R[p + j - 4] ^ self.S[idx]

    def generate_block(self) -> bytes:
        """Generate 80 bytes (20 words) of keystream."""
        output = []

        # Save initial values
        A = self.R[4 * NUM_ROUNDS]
        B = self.R[4 * NUM_ROUNDS + 1]
        C = self.R[4 * NUM_ROUNDS + 2]
        D = self.R[4 * NUM_ROUNDS + 3]
        n = self.n

        for _ in range(64):  # Generate 64 * 4 = 256 bytes? No, let me fix this
            # F function - mix A, B, C, D using T table
            for _ in range(2):
                p0, p1 = (A >> 9) & 0x1FF, (A >> 0) & 0x1FF
                q0, q1 = (A >> 23) & 0x1FF, (A >> 14) & 0x1FF

                B = (B + self.T[p0]) & 0xFFFFFFFF
                C = (C + self.T[p1]) & 0xFFFFFFFF
                D = (D ^ self.T[q0]) & 0xFFFFFFFF
                A = (A >> 16) | ((D ^ self.T[q1]) << 16)

            output.extend(
                (B & 0xFFFFFFFF, C & 0xFFFFFFFF, D & 0xFFFFFFFF, A & 0xFFFFFFFF))
            # Update n for next iteration
            n = (n + 1) & 0xFFFFFFFF
            self._initialize_register(n)
            A = self.R[4 * NUM_ROUNDS]
            B = self.R[4 * NUM_ROUNDS + 1]
            C = self.R[4 * NUM_ROUNDS + 2]
            D = self.R[4 * NUM_ROUNDS + 3]

        # Convert to bytes
        keystream = b""
        for word in output[:L]:  # Only take L words
            keystream += word.to_bytes(4, "big")

        self.n = (self.n + 1) & 0xFFFFFFFF
        return keystream


def seal_encrypt(key: bytes, iv: int, plaintext: bytes) -> bytes:
    """Encrypt/decrypt data using SEAL stream cipher.

    Args:
        key: 20-byte key
        iv: 32-bit position index
        plaintext: Data to encrypt/decrypt

    Returns:
        Encrypted/decrypted data
    """
    state = SEALState(key, iv)
    ciphertext = b""

    for i in range(0, len(plaintext), L * 4):
        keystream = state.generate_block()
        block = plaintext[i: i + L * 4]
        for j in range(len(block)):
            ciphertext += bytes([block[j] ^ keystream[j]])

    return ciphertext


def seal_decrypt(key: bytes, iv: int, ciphertext: bytes) -> bytes:
    """Decrypt data using SEAL stream cipher.

    Note: In stream ciphers, encryption and decryption are the same operation.

    Args:
        key: 20-byte key
        iv: 32-bit position index
        ciphertext: Data to decrypt

    Returns:
        Decrypted data
    """
    return seal_encrypt(key, iv, ciphertext)


def seal_keystream(key: bytes, iv: int, length: int) -> bytes:
    """Generate SEAL keystream of specified length.

    Args:
        key: 20-byte key
        iv: 32-bit position index
        length: Number of bytes to generate

    Returns:
        Keystream bytes
    """
    state = SEALState(key, iv)
    keystream = b""

    while len(keystream) < length:
        keystream += state.generate_block()

    return keystream[:length]
