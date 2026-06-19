"""SHAKE extendable-output functions (XOF)."""

from .shake128 import SHAKE128, shake128, shake128_hex
from .shake256 import SHAKE256, shake256, shake256_hex

__all__ = [
  "SHAKE128",
  "SHAKE256",
  "shake128",
  "shake128_hex",
  "shake256",
  "shake256_hex",
]
