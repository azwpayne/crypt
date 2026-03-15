"""Pure Python implementation of BLAKE2b and BLAKE2s hash algorithms.

BLAKE2 is a cryptographic hash function faster than MD5, SHA-1, and SHA-256,
while providing at least as much security as SHA-3.

Reference: RFC 7693
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence

# BLAKE2b constants (64-bit words)
# IV is the first 64 bits of the fractional parts of the square roots of the first 8 primes
BLAKE2B_IV: Final[tuple[int, ...]] = (
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

# BLAKE2s constants (32-bit words)
# IV is the first 32 bits of the fractional parts of the square roots of the first 8 primes
BLAKE2S_IV: Final[tuple[int, ...]] = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

# Sigma permutation for BLAKE2b (12 rounds)
# Each round uses a different permutation of message word indices
SIGMA: Final[tuple[tuple[int, ...], ...]] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
)


def _rotr64(x: int, n: int) -> int:
    """Rotate a 64-bit value right by n bits."""
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    """Rotate a 32-bit value right by n bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _blake2b_mix(
    v: list[int],
    a: int,
    b: int,
    c: int,
    d: int,
    x: int,
    y: int,
) -> None:
    """BLAKE2b mixing function (G function from RFC 7693).

    Args:
        v: Working vector (16 x 64-bit words)
        a, b, c, d: Indices into v
        x, y: Message words to mix in
    """
    v[a] = (v[a] + v[b] + x) & 0xFFFFFFFFFFFFFFFF
    v[d] = _rotr64(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFFFFFFFFFF
    v[b] = _rotr64(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & 0xFFFFFFFFFFFFFFFF
    v[d] = _rotr64(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFFFFFFFFFF
    v[b] = _rotr64(v[b] ^ v[c], 63)


def _blake2s_mix(
    v: list[int],
    a: int,
    b: int,
    c: int,
    d: int,
    x: int,
    y: int,
) -> None:
    """BLAKE2s mixing function (G function from RFC 7693).

    Args:
        v: Working vector (16 x 32-bit words)
        a, b, c, d: Indices into v
        x, y: Message words to mix in
    """
    v[a] = (v[a] + v[b] + x) & 0xFFFFFFFF
    v[d] = _rotr32(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFF
    v[b] = _rotr32(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & 0xFFFFFFFF
    v[d] = _rotr32(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFF
    v[b] = _rotr32(v[b] ^ v[c], 7)


def _blake2b_compress(
    h: list[int],
    block: bytes,
    t: int,
    f: bool,
) -> None:
    """BLAKE2b compression function.

    Args:
        h: State vector (8 x 64-bit words), modified in place
        block: 128-byte message block
        t: Block counter (bytes compressed so far)
        f: Finalization flag
    """
    # Convert block to 16 x 64-bit words (little-endian)
    m = list(struct.unpack("<16Q", block))

    # Initialize working vector v[0..15]
    v = h[:] + list(BLAKE2B_IV)

    # XOR with counter and flags
    v[12] ^= t & 0xFFFFFFFFFFFFFFFF
    v[13] ^= (t >> 64) & 0xFFFFFFFFFFFFFFFF
    if f:
        v[14] ^= 0xFFFFFFFFFFFFFFFF

    # 12 rounds
    for i in range(12):
        s = SIGMA[i]
        _blake2b_mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        _blake2b_mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        _blake2b_mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        _blake2b_mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        _blake2b_mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        _blake2b_mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        _blake2b_mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        _blake2b_mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])

    # Update state
    for i in range(8):
        h[i] ^= v[i] ^ v[i + 8]


def _blake2s_compress(
    h: list[int],
    block: bytes,
    t: int,
    f: bool,
) -> None:
    """BLAKE2s compression function.

    Args:
        h: State vector (8 x 32-bit words), modified in place
        block: 64-byte message block
        t: Block counter (bytes compressed so far)
        f: Finalization flag
    """
    # Convert block to 16 x 32-bit words (little-endian)
    m = list(struct.unpack("<16I", block))

    # Initialize working vector v[0..15]
    v = h[:] + list(BLAKE2S_IV)

    # XOR with counter and flags
    v[12] ^= t & 0xFFFFFFFF
    v[13] ^= (t >> 32) & 0xFFFFFFFF
    if f:
        v[14] ^= 0xFFFFFFFF

    # 10 rounds
    for i in range(10):
        s = SIGMA[i]
        _blake2s_mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        _blake2s_mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        _blake2s_mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        _blake2s_mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        _blake2s_mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        _blake2s_mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        _blake2s_mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        _blake2s_mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])

    # Update state
    for i in range(8):
        h[i] ^= v[i] ^ v[i + 8]


def blake2b(
    data: bytes,
    digest_size: int = 64,
    key: bytes = b"",
    salt: bytes = b"",
    person: bytes = b"",
) -> str:
    """Compute BLAKE2b hash of input data.

    Args:
        data: Input data to hash
        digest_size: Desired digest size in bytes (1-64, default 64)
        key: Optional key for keyed hashing (0-64 bytes)
        salt: Optional salt (0-16 bytes)
        person: Optional personalization (0-16 bytes)

    Returns:
        Hexadecimal hash string of length 2*digest_size

    Example:
        >>> blake2b(b"hello")
        '324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf...'
    """
    if not 1 <= digest_size <= 64:
        msg = "digest_size must be between 1 and 64"
        raise ValueError(msg)
    if len(key) > 64:
        msg = "key must be at most 64 bytes"
        raise ValueError(msg)
    if len(salt) > 16:
        msg = "salt must be at most 16 bytes"
        raise ValueError(msg)
    if len(person) > 16:
        msg = "person must be at most 16 bytes"
        raise ValueError(msg)

    # Initialize state with IV
    h = list(BLAKE2B_IV)

    # XOR parameter block into first 4 state words
    # P[0] = digest_size | key_len << 8 | fanout << 16 | depth << 24
    # P[1] = leaf_length (for BLAKE2b, this is leaf_length)
    # P[2] = node_offset (lower 32 bits)
    # P[3] = node_offset (upper 32 bits) | node_depth << 16 | inner_length << 24
    # P[4..5] = reserved
    # P[6..7] = salt (16 bytes)
    # P[8..9] = personal (16 bytes)

    key_len = len(key)
    h[0] ^= digest_size | (key_len << 8) | (1 << 16) | (1 << 24)

    # XOR salt into h[4..5]
    salt_padded = salt.ljust(16, b"\x00")
    h[4] ^= struct.unpack("<Q", salt_padded[:8])[0]
    h[5] ^= struct.unpack("<Q", salt_padded[8:])[0]

    # XOR personalization into h[6..7]
    person_padded = person.ljust(16, b"\x00")
    h[6] ^= struct.unpack("<Q", person_padded[:8])[0]
    h[7] ^= struct.unpack("<Q", person_padded[8:])[0]

    # Prepend key if present
    if key:
        data = key.ljust(128, b"\x00") + data

    # Pad message to multiple of 128 bytes
    original_len = len(data)
    if original_len % 128 != 0:
        data = data + b"\x00" * (128 - (original_len % 128))

    # Process blocks
    num_blocks = len(data) // 128
    for i in range(num_blocks):
        block = data[i * 128 : (i + 1) * 128]
        is_last = i == num_blocks - 1
        t = (i + (1 if key else 0)) * 128
        _blake2b_compress(h, block, t, is_last)

    # Output digest
    result = b"".join(struct.pack("<Q", x) for x in h)
    return result[:digest_size].hex()


def blake2s(
    data: bytes,
    digest_size: int = 32,
    key: bytes = b"",
    salt: bytes = b"",
    person: bytes = b"",
) -> str:
    """Compute BLAKE2s hash of input data.

    Args:
        data: Input data to hash
        digest_size: Desired digest size in bytes (1-32, default 32)
        key: Optional key for keyed hashing (0-32 bytes)
        salt: Optional salt (0-8 bytes)
        person: Optional personalization (0-8 bytes)

    Returns:
        Hexadecimal hash string of length 2*digest_size

    Example:
        >>> blake2s(b"hello")
        '19213bacc58dee6dbde3ceb9a47cbb330b3d86f6cca899647eb9f725cf73...'
    """
    if not 1 <= digest_size <= 32:
        msg = "digest_size must be between 1 and 32"
        raise ValueError(msg)
    if len(key) > 32:
        msg = "key must be at most 32 bytes"
        raise ValueError(msg)
    if len(salt) > 8:
        msg = "salt must be at most 8 bytes"
        raise ValueError(msg)
    if len(person) > 8:
        msg = "person must be at most 8 bytes"
        raise ValueError(msg)

    # Initialize state with IV
    h = list(BLAKE2S_IV)

    # XOR parameter block into first 4 state words
    key_len = len(key)
    h[0] ^= digest_size | (key_len << 8) | (1 << 16) | (1 << 24)

    # XOR salt into h[4..5] (as two 32-bit words)
    salt_padded = salt.ljust(8, b"\x00")
    h[4] ^= struct.unpack("<I", salt_padded[:4])[0]
    h[5] ^= struct.unpack("<I", salt_padded[4:])[0]

    # XOR personalization into h[6..7]
    person_padded = person.ljust(8, b"\x00")
    h[6] ^= struct.unpack("<I", person_padded[:4])[0]
    h[7] ^= struct.unpack("<I", person_padded[4:])[0]

    # Prepend key if present
    if key:
        data = key.ljust(64, b"\x00") + data

    # Pad message to multiple of 64 bytes
    original_len = len(data)
    if original_len % 64 != 0:
        data = data + b"\x00" * (64 - (original_len % 64))

    # Process blocks
    num_blocks = len(data) // 64
    for i in range(num_blocks):
        block = data[i * 64 : (i + 1) * 64]
        is_last = i == num_blocks - 1
        t = (i + (1 if key else 0)) * 64
        _blake2s_compress(h, block, t, is_last)

    # Output digest
    result = b"".join(struct.pack("<I", x) for x in h)
    return result[:digest_size].hex()
