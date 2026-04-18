"""SHA (Secure Hash Algorithm) family implementations.

This package provides:
- SHA-0
- SHA-1 (deprecated)
- SHA-2: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- SHA-3: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- Keccak: SHA3-KE-128, SHA3-KE-224, SHA3-KE-256, SHA3-KE-384, SHA3-KE-512
"""

# Import the actual module files
from . import (
    sha0,
    sha1,
    sha2_224,
    sha2_256,
    sha2_384,
    sha2_512,
    sha2_512_224,
    sha2_512_256,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    sha3_ke_128,
    sha3_ke_224,
    sha3_ke_256,
    sha3_ke_384,
    sha3_ke_512,
    sha_512_224,
    sha_512_256,
    sha_iv,
    sha_k,
)

# Aliases for consistent naming (sha2_224 -> sha224, etc.)
sha224 = sha2_224
sha256 = sha2_256
sha384 = sha2_384
sha512 = sha2_512
sha512_224 = sha2_512_224
sha512_256 = sha2_512_256

__all__ = [
    "sha0",
    "sha1",
    "sha2_224",
    "sha2_256",
    "sha2_384",
    "sha2_512",
    "sha2_512_224",
    "sha2_512_256",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "sha3_ke_128",
    "sha3_ke_224",
    "sha3_ke_256",
    "sha3_ke_384",
    "sha3_ke_512",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512_224",
    "sha512_256",
    "sha_512_224",
    "sha_512_256",
    "sha_iv",
    "sha_k",
]
