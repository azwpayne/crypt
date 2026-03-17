"""SHAKE extendable-output functions (XOF)."""

from .shake128 import SHAKE128, shake128, shake128_hex
from .shake256 import SHAKE256, shake256, shake256_hex

__all__ = [
    "SHAKE128",
    "shake128",
    "shake128_hex",
    "SHAKE256",
    "shake256",
    "shake256_hex",
]
