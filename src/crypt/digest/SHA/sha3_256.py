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

from crypt.digest.SHA.utils import bytes_to_lanes, keccak_f_1600, lanes_to_bytes

# SHA3-256 parameters
SHA3_256_RATE = 136  # Rate in bytes (1088 bits)
SHA3_256_CAPACITY = 64  # Capacity in bytes (512 bits)
SHA3_256_OUTPUT_LENGTH = 32  # Output length in bytes (256 bits)


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
        block_lanes = bytes_to_lanes(block.ljust(200, b"\x00"))

        # XOR block into state
        for j in range(len(block_lanes)):
            state[j] ^= block_lanes[j]

        # Apply permutation
        state = keccak_f_1600(state)

    # Squeeze phase
    output = bytearray()
    while len(output) < SHA3_256_OUTPUT_LENGTH:
        output.extend(lanes_to_bytes(state)[:SHA3_256_RATE])
        if len(output) < SHA3_256_OUTPUT_LENGTH:
            state = keccak_f_1600(state)

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
