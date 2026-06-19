"""Modern stream cipher implementations.

Stream ciphers that are (or were) used in real cryptographic systems:
ChaCha20, RC4, Salsa20, Rabbit, Trivium, SEAL, ZUC.

Historical / classical ciphers (Caesar, ROT13, Vigenère, Atbash, Affine,
Polybius, Simple Substitution) have moved to :mod:`crypt.classical`.
"""

__all__ = [
  "chacha20",
  "rabbit",
  "rc4",
  "salsa20",
  "seal",
  "trivium",
  "zuc",
]

from . import (
  chacha20,
  rabbit,
  rc4,
  salsa20,
  seal,
  trivium,
  zuc,
)
