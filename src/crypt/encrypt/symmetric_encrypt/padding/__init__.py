"""Padding schemes for block ciphers."""

from .ansi_x923 import pad as ansi_x923_pad
from .ansi_x923 import unpad as ansi_x923_unpad
from .pkcs7 import pad as pkcs7_pad
from .pkcs7 import unpad as pkcs7_unpad

__all__ = [
  "PaddingError",
  "ansi_x923_pad",
  "ansi_x923_unpad",
  "pkcs7_pad",
  "pkcs7_unpad",
]


class PaddingError(ValueError):
  """Invalid padding bytes detected."""
