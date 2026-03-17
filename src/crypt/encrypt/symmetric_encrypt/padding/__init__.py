"""Padding schemes for block ciphers."""

from .pkcs7 import pad as pkcs7_pad, unpad as pkcs7_unpad

__all__ = ["pkcs7_pad", "pkcs7_unpad", "PaddingError"]


class PaddingError(ValueError):
    """Invalid padding bytes detected."""
    pass
