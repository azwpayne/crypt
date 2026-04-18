"""Encoding schemes for binary-to-text conversion.

This package provides implementations of various encoding schemes:
- Base16, Base32, Base36, Base58, Base62, Base64, Base85, Base91, Base92
- URL encoding
- HTML entity encoding
- Quoted-Printable encoding
- Morse code
- ROT13/ROT47
"""

__all__ = [
  "ascii_module",
  "base16",
  "base32",
  "base36",
  "base58",
  "base62",
  "base64",
  "base85",
  "base91",
  "base92",
  "hex2bin",
  "html",
  "morse_code",
  "quoted_printable",
  "rot47",
  "url",
]

from crypt.encode import (
  ascii as ascii_module,
)
from crypt.encode import (
  base16,
  base32,
  base36,
  base58,
  base62,
  base64,
  base85,
  base91,
  base92,
  hex2bin,
  html,
  morse_code,
  quoted_printable,
  rot47,
  url,
)
