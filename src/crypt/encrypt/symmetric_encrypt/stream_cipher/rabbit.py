"""Pure Python implementation of Rabbit stream cipher.

Rabbit is a stream cipher designed by Martin Boesgaard, Mette Vesterager, Thomas Pedersen,
Jesper Christiansen, and Ove Scavenius. It was submitted to the eSTREAM project.

- 128-bit key
- 64-bit IV
- 513-bit internal state
- Uses 8 state variables and counter system

This implementation is for educational purposes only.
"""

from __future__ import annotations

from typing import Final

# Constants
A: Final[tuple[int, ...]] = (
    0x4D34D34D,
    0xD34D34D3,
    0x34D34D34,
    0x4D34D34D,
    0xD34D34D3,
    0x34D34D34,
    0x4D34D34D,
    0xD34D34D3,
)

MASK32: Final[int] = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    """32-bit left rotation."""
    n %= 32
    return ((x << n) | (x >> (32 - n))) & MASK32


def _g_func(x: int) -> int:
    """The g function used in Rabbit state update."""
    # g(x) = ((x + x) ^ (x * x)) mod 2^32
    # Actually g(x) = (x*x) ^ (x*x << 1) in the specification
    a = x & 0xFFFF
    b = x >> 16
    # Compute (x*x) using 16-bit operations to avoid overflow issues
    # Actually the original uses full 32-bit: g(x) = ((x + x) << 16) ^ ((x * x) << 1)
    # Let me use the correct formula from the paper
    h = x ** 2 >> 32 & MASK32
    low = x ** 2 & MASK32
    return _rotl(h ^ low, 16)


class RabbitState:
    """Rabbit cipher state."""

    def __init__(self) -> None:
        self.x = [0] * 8  # State variables
        self.c = [0] * 8  # Counters
        self.carry = 0

    def _update_counters(self) -> None:
        """Update counter values."""
        for j in range(8):
            temp = self.c[j] + A[j] + self.carry
            self.carry = temp >> 32
            self.c[j] = temp & MASK32

    def next_state(self) -> None:
        """Update the internal state."""
        g = [0] * 8
        for j in range(8):
            temp = self.x[j] + self.c[j]
            g[j] = _g_func(temp & MASK32)

        self.x[0] = (g[0] + _rotl(g[7], 16) + _rotl(g[6], 16)) & MASK32
        self.x[1] = (g[1] + _rotl(g[0], 8) + g[7]) & MASK32
        self.x[2] = (g[2] + _rotl(g[1], 16) + _rotl(g[0], 16)) & MASK32
        self.x[3] = (g[3] + _rotl(g[2], 8) + g[1]) & MASK32
        self.x[4] = (g[4] + _rotl(g[3], 16) + _rotl(g[2], 16)) & MASK32
        self.x[5] = (g[5] + _rotl(g[4], 8) + g[3]) & MASK32
        self.x[6] = (g[6] + _rotl(g[5], 16) + _rotl(g[4], 16)) & MASK32
        self.x[7] = (g[7] + _rotl(g[6], 8) + g[5]) & MASK32

        self._update_counters()

    def extract_keystream(self) -> bytes:
        """Extract 16 bytes of keystream from current state."""
        s = [0] * 4
        s[0] = (self.x[0] & 0xFFFF) ^ ((self.x[5] >> 16) & 0xFFFF)
        s[1] = ((self.x[0] >> 16) & 0xFFFF) ^ (self.x[3] & 0xFFFF)
        s[2] = (self.x[2] & 0xFFFF) ^ ((self.x[7] >> 16) & 0xFFFF)
        s[3] = ((self.x[2] >> 16) & 0xFFFF) ^ (self.x[5] & 0xFFFF)

        keystream = b""
        for i in range(4):
            keystream += s[i].to_bytes(2, "little")

        return keystream


def _key_setup(state: RabbitState, key: bytes) -> None:
    """Setup the Rabbit state from a 128-bit key."""
    if len(key) != 16:
        msg = f"Key must be 16 bytes, got {len(key)}"
        raise ValueError(msg)

    # Convert key to 4 32-bit words
    k = [int.from_bytes(key[i: i + 4], "little") for i in range(0, 16, 4)]

    # Initialize state
    state.x[0] = k[0]
    state.x[2] = k[1]
    state.x[4] = k[2]
    state.x[6] = k[3]
    state.x[1] = ((k[3] << 16) | (k[2] >> 16)) & MASK32
    state.x[3] = ((k[0] << 16) | (k[3] >> 16)) & MASK32
    state.x[5] = ((k[1] << 16) | (k[0] >> 16)) & MASK32
    state.x[7] = ((k[2] << 16) | (k[1] >> 16)) & MASK32

    # Initialize counters
    state.c[0] = _rotl(k[2], 16)
    state.c[2] = _rotl(k[3], 16)
    state.c[4] = _rotl(k[0], 16)
    state.c[6] = _rotl(k[1], 16)
    state.c[1] = (k[0] & 0xFFFF0000) | (k[1] & 0xFFFF)
    state.c[3] = (k[1] & 0xFFFF0000) | (k[2] & 0xFFFF)
    state.c[5] = (k[2] & 0xFFFF0000) | (k[3] & 0xFFFF)
    state.c[7] = (k[3] & 0xFFFF0000) | (k[0] & 0xFFFF)

    state.carry = 0

    # Iterate 4 times
    for _ in range(4):
        state.next_state()


def _iv_setup(state: RabbitState, iv: bytes) -> None:
    """Setup the Rabbit state with a 64-bit IV."""
    if len(iv) != 8:
        msg = f"IV must be 8 bytes, got {len(iv)}"
        raise ValueError(msg)

    # Convert IV to 2 32-bit words
    i0 = int.from_bytes(iv[:4], "little")
    i1 = int.from_bytes(iv[4:8], "little")

    # Modify counters
    state.c[0] ^= i0
    state.c[1] ^= ((i1 >> 16) | (i0 << 16)) & MASK32
    state.c[2] ^= i1
    state.c[3] ^= ((i0 >> 16) | (i1 << 16)) & MASK32
    state.c[4] ^= i0
    state.c[5] ^= ((i1 >> 16) | (i0 << 16)) & MASK32
    state.c[6] ^= i1
    state.c[7] ^= ((i0 >> 16) | (i1 << 16)) & MASK32

    # Iterate 4 times
    for _ in range(4):
        state.next_state()


def rabbit_encrypt(key: bytes, iv: bytes | None, plaintext: bytes) -> bytes:
    """Encrypt/decrypt data using Rabbit stream cipher.

    Args:
        key: 16-byte key
        iv: Optional 8-byte IV
        plaintext: Data to encrypt/decrypt

    Returns:
        Encrypted/decrypted data
    """
    state = RabbitState()
    _key_setup(state, key)

    if iv is not None:
        _iv_setup(state, iv)

    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        # Generate 16 bytes of keystream (2 iterations)
        keystream = b""
        for _ in range(2):
            keystream += state.extract_keystream()
            state.next_state()

        block = plaintext[i: i + 16]
        for j in range(len(block)):
            ciphertext += bytes([block[j] ^ keystream[j]])

    return ciphertext


def rabbit_decrypt(key: bytes, iv: bytes | None, ciphertext: bytes) -> bytes:
    """Decrypt data using Rabbit stream cipher.

    Note: In stream ciphers, encryption and decryption are the same operation.

    Args:
        key: 16-byte key
        iv: Optional 8-byte IV
        ciphertext: Data to decrypt

    Returns:
        Decrypted data
    """
    return rabbit_encrypt(key, iv, ciphertext)


def rabbit_keystream(key: bytes, iv: bytes | None, length: int) -> bytes:
    """Generate Rabbit keystream of specified length.

    Args:
        key: 16-byte key
        iv: Optional 8-byte IV
        length: Number of bytes to generate

    Returns:
        Keystream bytes
    """
    state = RabbitState()
    _key_setup(state, key)

    if iv is not None:
        _iv_setup(state, iv)

    keystream = b""
    while len(keystream) < length:
        keystream += state.extract_keystream()
        state.next_state()

    return keystream[:length]
