"""Pure Python implementation of X25519 ECDH key exchange.

X25519 is an Elliptic Curve Diffie-Hellman key exchange based on RFC 7748.
It uses Curve25519 in Montgomery form with the equation:
    y² = x³ + 486662x² + x
over GF(2^255-19).

This implementation is for educational purposes only.
"""

from __future__ import annotations

import os
from typing import Final

# Curve parameters
P: Final[int] = 2**255 - 19  # Prime field
A: Final[int] = 486662  # Curve constant
A24: Final[int] = (A - 2) // 4  # (A - 2) / 4 = 121666

# Base point x-coordinate
BASE_X: Final[int] = 9


def _modp_inv(x: int) -> int:
    """Compute modular inverse mod P using Fermat's little theorem."""
    return pow(x % P, P - 2, P)


def _montgomery_ladder(scalar: int, x: int) -> int:
    """Montgomery ladder for scalar multiplication.

    Computes scalar * point where point has x-coordinate x.
    Implementation following RFC 7748 section 5.

    Args:
        scalar: 256-bit scalar (already clamped)
        x: x-coordinate of point

    Returns:
        x-coordinate of result
    """
    x1 = x % P
    x2, z2 = 1, 0  # Point at infinity
    x3, z3 = x1, 1  # Base point
    swap = 0

    for t in range(255, -1, -1):
        k_t = (scalar >> t) & 1
        swap ^= k_t

        # Conditional swap
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t

        # Montgomery ladder step
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) * (da + cb)) % P
        z3 = (x1 * ((da - cb) * (da - cb))) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + A24 * e)) % P

    # Final conditional swap
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    # Return x2/z2
    return (x2 * _modp_inv(z2)) % P


def _clamp_scalar(scalar: bytes) -> int:
    """Clamp private key according to RFC 7748.

    - Clear bits 0, 1, 2 (make divisible by 8)
    - Set bit 254
    - Clear bit 255
    """
    if len(scalar) != 32:
        msg = "Scalar must be 32 bytes"
        raise ValueError(msg)

    s = bytearray(scalar)
    s[0] &= 248  # Clear bits 0, 1, 2
    s[31] &= 127  # Clear bit 255
    s[31] |= 64  # Set bit 254

    return int.from_bytes(s, "little")


def generate_private_key() -> bytes:
    """Generate random X25519 private key.

    Returns:
        32-byte private key (properly clamped per RFC 7748)
    """
    return os.urandom(32)


def generate_public_key(private_key: bytes) -> bytes:
    """Generate public key from private key.

    Args:
        private_key: 32-byte private key

    Returns:
        32-byte public key (x-coordinate)
    """
    scalar = _clamp_scalar(private_key)
    public_x = _montgomery_ladder(scalar, BASE_X)
    return public_x.to_bytes(32, "little")


def compute_shared_secret(private_key: bytes, public_key: bytes) -> bytes:
    """Compute shared secret using X25519 ECDH.

    Args:
        private_key: Our 32-byte private key
        public_key: Peer's 32-byte public key

    Returns:
        32-byte shared secret
    """
    if len(private_key) != 32:
        msg = "Private key must be 32 bytes"
        raise ValueError(msg)
    if len(public_key) != 32:
        msg = "Public key must be 32 bytes"
        raise ValueError(msg)

    scalar = _clamp_scalar(private_key)
    peer_x = int.from_bytes(public_key, "little")

    shared_x = _montgomery_ladder(scalar, peer_x)
    return shared_x.to_bytes(32, "little")
