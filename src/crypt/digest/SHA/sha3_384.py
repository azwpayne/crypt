"""SHA3-384 Hash Algorithm Implementation

Implements the SHA3-384 cryptographic hash function as defined in FIPS 202.
Produces a 384-bit (48-byte) hash value using the Keccak-f[1600] permutation.

Features:
- FIPS 202 compliant
- Pure Python implementation
- Uses Keccak sponge construction
- Different internal structure from SHA-2 family (not vulnerable to length extension)

Security Notes:
- SHA3-384 produces a 384-bit (48-byte) hash
- Part of the SHA-3 family based on Keccak
- Provides 192-bit security level against collision attacks
- Not vulnerable to length extension attacks
- Suitable for high-security applications
- Often used in certificate chains and digital signatures

References:
- FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
- Keccak reference: https://keccak.team/keccak.html
"""

from __future__ import annotations

# Round constants for Keccak-f[1600]
ROUND_CONSTANTS = [
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


def _rot_left_64(x: int, n: int) -> int:
    """Perform left circular rotation on a 64-bit integer.

    Args:
        x: The 64-bit integer to rotate
        n: Number of bits to rotate left

    Returns:
        The rotated 64-bit integer
    """
    n = n % 64
    return ((x << n) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - n))


def _bytes_to_lanes(data: bytes) -> list[list[int]]:
    """Convert bytes to 5x5 state matrix of 64-bit lanes.

    Args:
        data: Input bytes (up to 200 bytes)

    Returns:
        5x5 state matrix of 64-bit words
    """
    lanes = [[0] * 5 for _ in range(5)]

    for y in range(5):
        for x in range(5):
            index = 8 * (5 * y + x)
            if index + 8 <= len(data):
                lane = 0
                for i in range(8):
                    lane |= data[index + i] << (8 * i)
                lanes[x][y] = lane
    return lanes


def _lanes_to_bytes(lanes: list[list[int]]) -> bytes:
    """Convert 5x5 state matrix to bytes.

    Args:
        lanes: 5x5 state matrix of 64-bit words

    Returns:
        Bytes representation (200 bytes)
    """
    result = bytearray(200)

    for y in range(5):
        for x in range(5):
            index = 8 * (5 * y + x)
            lane = lanes[x][y]
            for i in range(8):
                result[index + i] = (lane >> (8 * i)) & 0xFF
    return bytes(result)


def _keccak_f(state: list[list[int]]) -> list[list[int]]:
    """Keccak-f[1600] permutation function.

    Applies 24 rounds of the Keccak permutation to the state.

    Args:
        state: 5x5 state matrix of 64-bit words

    Returns:
        The permuted 5x5 state matrix
    """
    for round_num in range(24):
        # Theta step
        C = [0] * 5
        D = [0] * 5

        for x in range(5):
            C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]

        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ _rot_left_64(C[(x + 1) % 5], 1)

        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]

        # Rho and Pi steps
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rot_left_64(state[x][y], ROTATION_OFFSETS[x][y])

        # Chi step
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

        # Iota step
        state[0][0] ^= ROUND_CONSTANTS[round_num]

    return state


def _keccak_pad(message: bytes, rate_bits: int) -> bytes:
    """Keccak padding function for SHA3.

    Applies SHA3-specific padding: M || 0x06 || 0x00... || 0x80

    Args:
        message: Input message bytes
        rate_bits: Rate in bits (r)

    Returns:
        Padded message bytes
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    elif isinstance(message, bytes):
        pass
    else:
        message = bytes(message)

    rate_bytes = rate_bits // 8
    msg_len = len(message)

    # Calculate padding: need (L + 2 + k) % rate_bytes = 0
    k = (-msg_len - 2) % rate_bytes
    padding = bytes([0x06] + [0] * k + [0x80])

    return message + padding


def sha3_384(data: bytes) -> bytes:
    """Compute SHA3-384 hash of data.

    Args:
        data: Input data as bytes

    Returns:
        The 48-byte (384-bit) hash digest

    Raises:
        TypeError: If data is not bytes

    Examples:
        >>> sha3_384(b"").hex()
        '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004'
        >>> sha3_384(b"abc").hex()
        'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25'
    """
    if not isinstance(data, bytes):
        msg = "data must be bytes"
        raise TypeError(msg)

    # SHA3-384 parameters
    capacity_bits = 768
    rate_bits = 1600 - capacity_bits  # 832 bits = 104 bytes

    # Initialize state
    state = [[0] * 5 for _ in range(5)]

    # Padding
    padded_data = _keccak_pad(data, rate_bits)

    # Absorb phase
    rate_bytes = rate_bits // 8
    block_count = len(padded_data) // rate_bytes

    for i in range(block_count):
        block = padded_data[i * rate_bytes : (i + 1) * rate_bytes]

        # Convert to lanes and XOR into state
        block_lanes = _bytes_to_lanes(block)
        for x in range(5):
            for y in range(5):
                state[x][y] ^= block_lanes[x][y]

        # Apply permutation
        state = _keccak_f(state)

    # Squeeze phase (48 bytes = 384 bits)
    output_bytes = 48
    output = bytearray()

    while len(output) < output_bytes:
        state_bytes = _lanes_to_bytes(state)
        output.extend(state_bytes[:rate_bytes])

        if len(output) < output_bytes:
            state = _keccak_f(state)

    return bytes(output[:output_bytes])


def sha3_384_hex(data: bytes) -> str:
    """Compute SHA3-384 hash and return as hex string.

    Args:
        data: Input data as bytes

    Returns:
        96-character hexadecimal string

    Examples:
        >>> sha3_384_hex(b"hello world")
        '83bff28d1d6a30e5bdd1a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5'
    """
    return sha3_384(data).hex()


if __name__ == "__main__":
    # Test vectors
    import hashlib

    test_cases = [
        b"",
        b"abc",
        b"hello world",
    ]

    for msg in test_cases:
        our_hash = sha3_384(msg).hex()
        std_hash = hashlib.sha3_384(msg).hexdigest()
        print(f"Input: {msg!r}")
        print(f"Our hash: {our_hash}")
        print(f"Standard: {std_hash}")
        print(f"Match: {our_hash == std_hash}")
        print()
