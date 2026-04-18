"""Block cipher modes of operation.

This package provides:
- ECB (Electronic Codebook) - educational only
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)
- OFB (Output Feedback)
- CTR (Counter mode)
- XTS (XEX-based tweaked-codebook)
- EAX (Authenticated encryption)
- OCB (Offset Codebook Mode) - RFC 7253

Note: GCM and CCM are in the parent directory as stub implementations.
"""

from .cbc import CBCMode
from .cfb import CFBMode
from .ctr import CTRMode, ModeError
from .ecb import ECBMode
from .ocb import ocb_decrypt, ocb_encrypt
from .ofb import OFBMode

__all__ = [
    "CBCMode",
    "CFBMode",
    "CTRMode",
    "ECBMode",
    "ModeError",
    "OFBMode",
    "ocb_decrypt",
    "ocb_encrypt",
]
