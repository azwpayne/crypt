"""Cryptographic hash functions and message authentication codes.

This package provides implementations of:
- Hash functions (MD, SHA, BLAKE, SM3, etc.)
- HMAC (Hash-based Message Authentication)
- CMAC (Cipher-based Message Authentication)
- KDF (Key Derivation Functions: PBKDF2, scrypt, Argon2)
- MAC algorithms (Poly1305, SipHash)
- CRC checksums
"""

__all__ = [
    "adler32",
    "bcrypt",
    "blake2",
    "blake3",
    "fnv",
    "poly1305",
    "ripemd128",
    "ripemd160",
    "siphash",
    "sm3",
    "tiger",
    "whirlpool",
]

from crypt.digest import (
    adler32,
    bcrypt,
    blake2,
    blake3,
    fnv,
    poly1305,
    ripemd128,
    ripemd160,
    siphash,
    sm3,
    tiger,
    whirlpool,
)
