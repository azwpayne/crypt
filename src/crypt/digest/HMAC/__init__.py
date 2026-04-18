"""HMAC and CMAC implementations.

HMAC (Hash-based Message Authentication Code):
- HMAC-MD5
- HMAC-SHA1
- HMAC-SHA256

CMAC (Cipher-based Message Authentication Code):
- AES-CMAC
"""

__all__ = [
    "cmac",
    "hmac_md5",
    "hmac_sha1",
    "hmac_sha256",
]
