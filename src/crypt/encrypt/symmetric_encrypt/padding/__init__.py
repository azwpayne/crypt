"""Padding schemes for block ciphers."""

from .ansi_x923 import pad as ansi_x923_pad, unpad as ansi_x923_unpad
from .pkcs7 import pad as pkcs7_pad, unpad as pkcs7_unpad

__all__ = [
    "pkcs7_pad",
    "pkcs7_unpad",
    "ansi_x923_pad",
    "ansi_x923_unpad",
    "PaddingError",
]


class PaddingError(ValueError):
    """Invalid padding bytes detected."""
    pass
