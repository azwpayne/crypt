"""SHA3-256 Hash Algorithm Implementation

Implements the SHA3-256 cryptographic hash function as defined in FIPS 202.
Produces a 256-bit (32-byte) hash value using the Keccak-f[1600] permutation.

Features:
- FIPS 202 compliant
- Pure Python implementation
- Uses Keccak sponge construction
- Different internal structure from SHA-2 family (not vulnerable to length extension)

Security Notes:
- SHA3-256 produces a 256-bit (32-byte) hash
- Part of the SHA-3 family based on Keccak
- Different design philosophy from SHA-2 (sponge vs Merkle-Damgard)
- Not vulnerable to length extension attacks
- Provides 128-bit security level against collision attacks
- Recommended for new applications requiring 256-bit hash output

References:
- FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
- Keccak reference: https://keccak.team/keccak.html
"""

from __future__ import annotations

import struct

# SHA3-256 parameters
SHA3_256_RATE = 136  # Rate in bytes (1088 bits)
SHA3_256_CAPACITY = 64  # Capacity in bytes (512 bits)
SHA3_256_OUTPUT_LENGTH = 32  # Output length in bytes (256 bits)
KECCAK_F_WIDTH = 1600  # State width in bits
KECCAK_F_ROUNDS = 24  # Number of permutation rounds

# Round constants for Keccak-f[1600]
RC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]

# Rotation offsets for rho step
ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

# Pi permutation indices
PI_PERMUTATION = [
    0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20,
    4, 5, 11, 17, 23, 2, 8, 14, 15, 21,
]


def _rotate_left_64(x: int, n: int) -> int:
    """Perform left circular rotation on a 64-bit integer.

    Args:
        x: The 64-bit integer to rotate
        n: Number of bits to rotate left

    Returns:
        The rotated 64-bit integer
    """
    n = n % 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _bytes_to_lanes(data: bytes) -> list[int]:
    """Convert bytes to 25 64-bit lanes (little-endian).

    Args:
        data: Input bytes (up to 200 bytes)

    Returns:
        List of 25 64-bit integers
    """
    lanes = [0] * 25
    for i in range(min(len(data) // 8, 25)):
        lanes[i] = struct.unpack("<Q", data[i * 8 : (i + 1) * 8])[0]
    return lanes


def _lanes_to_bytes(lanes: list[int]) -> bytes:
    """Convert 25 64-bit lanes to bytes (little-endian).

    Args:
        lanes: List of 25 64-bit integers

    Returns:
        Bytes representation (200 bytes)
    """
    result = bytearray()
    for lane in lanes:
        result.extend(struct.pack("<Q", lane))
    return bytes(result)


def _keccak_f_1600(state: list[int]) -> list[int]:
    """Keccak-f[1600] permutation function.

    Applies 24 rounds of the Keccak permutation.

    Args:
        state: List of 25 64-bit integers representing the state

    Returns:
        Permuted state as list of 25 64-bit integers
    """
    # Convert to 5x5 matrix
    A = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            A[x][y] = state[x + 5 * y]

    # 24 rounds
    for round_num in range(KECCAK_F_ROUNDS):
        # Theta step
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotate_left_64(C[(x + 1) % 5], 1) for x in range(5)]

        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]

        # Rho and Pi steps
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotate_left_64(A[x][y], ROTATION_OFFSETS[x][y])

        # Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

        # Iota step
        A[0][0] ^= RC[round_num]

    # Convert back to list
    result = [0] * 25
    for x in range(5):
        for y in range(5):
            result[x + 5 * y] = A[x][y]

    return result


def _sha3_pad(message_len: int, rate: int) -> bytes:
    """SHA3 padding function.

    Applies multi-rate padding: 0x06 || 0x00... || 0x80

    Args:
        message_len: Length of message in bytes
        rate: Rate in bytes

    Returns:
        Padding bytes
    """
    pad_len = rate - (message_len % rate)
    if pad_len == 0:
        pad_len = rate

    padding = bytearray(pad_len)
    padding[0] = 0x06  # SHA3 domain separator
    padding[pad_len - 1] |= 0x80  # Final bit

    return bytes(padding)


def sha3_256(msg: bytes) -> bytes:
    """Compute SHA3-256 hash of message.

    Args:
        msg: Input message as bytes

    Returns:
        The 32-byte (256-bit) hash digest

    Raises:
        TypeError: If msg is not bytes

    Examples:
        >>> sha3_256(b"").hex()
        'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
        >>> sha3_256(b"abc").hex()
        '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'
    """
    if not isinstance(msg, bytes):
        msg_err = "msg must be bytes"
        raise TypeError(msg_err)

    # Initialize state
    state = [0] * 25

    # Padding
    padded_msg = msg + _sha3_pad(len(msg), SHA3_256_RATE)

    # Absorb phase
    for i in range(0, len(padded_msg), SHA3_256_RATE):
        block = padded_msg[i : i + SHA3_256_RATE]
        block_lanes = _bytes_to_lanes(block.ljust(200, b"\x00"))

        # XOR block into state
        for j in range(len(block_lanes)):
            state[j] ^= block_lanes[j]

        # Apply permutation
        state = _keccak_f_1600(state)

    # Squeeze phase
    output = bytearray()
    while len(output) < SHA3_256_OUTPUT_LENGTH:
        output.extend(_lanes_to_bytes(state)[:SHA3_256_RATE])
        if len(output) < SHA3_256_OUTPUT_LENGTH:
            state = _keccak_f_1600(state)

    return bytes(output)[:SHA3_256_OUTPUT_LENGTH]


def sha3_256_hex(msg: bytes) -> str:
    """Compute SHA3-256 hash and return as hex string.

    Args:
        msg: Input message as bytes

    Returns:
        64-character hexadecimal string

    Examples:
        >>> sha3_256_hex(b"hello world")
        '644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938'
    """
    return sha3_256(msg).hex()


if __name__ == "__main__":
    # Test vectors
    test_vectors = [
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ]

    for msg, expected in test_vectors:
        result = sha3_256_hex(msg)
        print(f"Input: {msg!r}")
        print(f"Expected: {expected}")
        print(f"Got:      {result}")
        print(f"Match: {result == expected}")
        print()
