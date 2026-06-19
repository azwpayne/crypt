"""Checksums / integrity verification (non-cryptographic).

Subpackage: crc. Standalone: adler32, fnv.
"""

from . import adler32, crc, fnv

__all__ = ["adler32", "crc", "fnv"]
