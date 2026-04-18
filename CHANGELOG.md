# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation for all modules
- Proper `__all__` exports in all `__init__.py` files
- English docstrings for base64, chacha20, sm3, zuc modules

### Changed
- Updated README.md to accurately reflect implemented algorithms
- Updated pyproject.toml with proper metadata, authors, license, and keywords
- Translated Chinese comments to English in source files

### Deprecated
- GCM mode (marked as stub implementation)
- CCM mode (marked as stub implementation)
- ZUC cipher (marked as stub/placeholder)

### Fixed
- Documentation now correctly lists BLAKE2b and BLAKE2s as separate algorithms
- Removed unimplemented algorithms from README (Grain, HC-128, SIV, IDEA, TEA, XXTEA)

## [0.1.0] - 2026-01-06

### Added
- Initial release with comprehensive cryptographic implementations
- Hash functions: MD, SHA, SHA3, BLAKE2, BLAKE3, SM3, Tiger, RIPEMD, Whirlpool
- Checksums: CRC family, Adler32, FNV
- HMAC and CMAC message authentication
- Key derivation: PBKDF2, scrypt, Argon2
- Block ciphers: AES, DES, 3DES, Blowfish, Twofish, Camellia, CAST, RC5, RC6, SM4, PRESENT, Simon
- Block cipher modes: ECB, CBC, CFB, OFB, CTR, XTS, EAX, OCB
- Stream ciphers: ChaCha20, ChaCha20-Poly1305, Salsa20, RC4, Rabbit, Trivium
- Classical ciphers: Playfair, Rail Fence
- Asymmetric encryption: RSA, RSA-PSS, DSA, ECC, ECDH, Ed25519, X25519, Diffie-Hellman, ElGamal, Paillier, NTRU
- Encoding schemes: Base16, Base32, Base36, Base58, Base62, Base64, Base85, Base91, Base92, URL, HTML, Quoted-Printable, ROT47, Morse Code
- Extensive test suite with 144 test files and 2694 test functions
- Support for Python 3.10-3.14
