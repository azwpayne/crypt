"""Pure Python cryptographic algorithms for educational purposes.

This package provides implementations of common cryptographic algorithms
including hash functions, symmetric and asymmetric encryption, and encoding schemes.

Example:
    >>> from crypt.hash.sha.sha2_256 import sha256
    >>> sha256(b"Hello")
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969'
"""

__version__ = "0.1.0"
__author__ = "azwpayne"
__email__ = "paynewu0719@gmail.com"

__all__ = [
  "asymmetric",
  "checksum",
  "classical",
  "e2e",
  "encode",
  "hash",
  "kdf",
  "mac",
  "symmetric",
]

from . import asymmetric, checksum, classical, e2e, encode, hash, kdf, mac, symmetric
