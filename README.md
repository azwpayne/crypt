# Crypt

A pure Python implementation of common cryptographic algorithms for educational
purposes.

## Overview

This library provides implementations of various cryptographic algorithms including hash
functions, symmetric and asymmetric encryption, and encoding schemes. The focus is on
clear, understandable implementations that demonstrate how these algorithms work under
the hood.

**Note**: This is an educational project. While the implementations are tested against
reference libraries, they are not optimized for production use and have not undergone
formal security audits.

## Installation

This project uses `uv` for dependency management:

```bash
# Clone the repository
git clone <repository-url>
cd crypt

# Install dependencies
uv sync

# Install with dev dependencies
uv sync --group dev

# Install with test dependencies
uv sync --group test
```

### Requirements

- Python >= 3.10
- uv (for dependency management)

## Quick Start

### Hash Functions

```python
from crypt.digest.MD.md5 import md5
from crypt.digest.SHA.sha2_256 import sha256

# MD5 hash (for educational purposes - not for security)
result = md5(b"Hello, World!")
print(result.hex())  # 65a8e27d8879283831b664bd8b7f0ad4

# SHA-256 hash
result = sha256(b"Hello, World!")
print(result.hex())  # dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```

### Symmetric Encryption

```python
from crypt.encrypt.symmetric_encrypt.block_cipher.aes import aes_encrypt, aes_decrypt

key = b"0123456789abcdef"  # 16 bytes for AES-128
plaintext = b"Hello, World!!!!"  # Must be 16 bytes (block size)

# Encrypt
ciphertext = aes_encrypt(plaintext, key)
print(f"Encrypted: {ciphertext.hex()}")

# Decrypt
decrypted = aes_decrypt(ciphertext, key)
print(f"Decrypted: {decrypted.decode()}")
```

### Encoding

```python
from crypt.encode.base64 import encode as b64_encode, decode as b64_decode
from crypt.encode.base58 import encode as b58_encode, decode as b58_decode

# Base64 encoding
data = b"Hello, World!"
encoded = b64_encode(data)
print(encoded)  # SGVsbG8sIFdvcmxkIQ==

decoded = b64_decode(encoded)
print(decoded)  # b"Hello, World!"

# Base58 encoding (commonly used in Bitcoin)
encoded = b58_encode(data)
print(encoded)  # 72k1xXWG59fYdzSNoA
decoded = b58_decode(encoded)
print(decoded)  # b"Hello, World!"
```

### Asymmetric Encryption

```python3
from crypt.encrypt.asymmetric_encrypt.rsa import generate_keypair, rsa_encrypt,
    rsa_decrypt

# Generate RSA key pair
public_key, private_key = generate_keypair(key_size = 2048)

# Encrypt
message = b"Hello, RSA!"
ciphertext = rsa_encrypt(message, public_key)

# Decrypt
decrypted = rsa_decrypt(ciphertext, private_key)
print(decrypted.decode())  # Hello, RSA!
```

## Implemented Algorithms

### Hash Functions

| Algorithm           | Description                      | Status      |
|---------------------|----------------------------------|-------------|
| **MD Family**       |                                  |             |
| MD2                 | 128-bit hash (legacy)            | Implemented |
| MD4                 | 128-bit hash (legacy)            | Implemented |
| MD5                 | 128-bit hash (broken, legacy)    | Implemented |
| MD6                 | Variable-length hash             | Implemented |
| **SHA Family**      |                                  |             |
| SHA-0               | 160-bit hash (broken)            | Implemented |
| SHA-1               | 160-bit hash (deprecated)        | Implemented |
| SHA-224             | 224-bit hash                     | Implemented |
| SHA-256             | 256-bit hash                     | Implemented |
| SHA-384             | 384-bit hash                     | Implemented |
| SHA-512             | 512-bit hash                     | Implemented |
| SHA-512/224         | 224-bit truncated SHA-512        | Implemented |
| SHA-512/256         | 256-bit truncated SHA-512        | Implemented |
| SHA3-224            | Keccak-based 224-bit             | Implemented |
| SHA3-256            | Keccak-based 256-bit             | Implemented |
| SHA3-384            | Keccak-based 384-bit             | Implemented |
| SHA3-512            | Keccak-based 512-bit             | Implemented |
| SHAKE128            | Extendable-output function (XOF) | Implemented |
| SHAKE256            | Extendable-output function (XOF) | Implemented |
| **Other Hashes**    |                                  |             |
| BLAKE2b / BLAKE2s   | Fast cryptographic hash          | Implemented |
| BLAKE3              | Modern fast hash                 | Implemented |
| CRC8 / CRC12        | Cyclic redundancy checks (8/12)  | Implemented |
| CRC16 / CRC16-CCITT | Cyclic redundancy checks (16)    | Implemented |
| CRC32 / CRC32C      | Cyclic redundancy checks (32)    | Implemented |
| CRC64               | Cyclic redundancy check (64)     | Implemented |
| Adler32             | Checksum algorithm               | Implemented |
| FNV                 | Non-cryptographic hash           | Implemented |
| Tiger               | 192-bit hash                     | Implemented |
| RIPEMD-128          | 128-bit hash                     | Implemented |
| RIPEMD-160          | 160-bit hash                     | Implemented |
| Whirlpool           | 512-bit hash                     | Implemented |
| SM3                 | Chinese national standard hash   | Implemented |
| bcrypt              | Password hashing                 | Implemented |
| Poly1305            | Message authentication code      | Implemented |

### HMAC (Hash-based Message Authentication)

- HMAC-MD5
- HMAC-SHA1
- HMAC-SHA256

### MAC (Message Authentication Code)

| Algorithm | Description                                   |
|-----------|-----------------------------------------------|
| CMAC      | AES-based MAC (NIST SP 800-38B, RFC 4493)     |
| SipHash   | Fast keyed hash for hash-table DoS protection |

### Key Derivation Functions (KDF)

| Algorithm | Description                              |
|-----------|------------------------------------------|
| PBKDF2    | Password-Based Key Derivation Function 2 |
| scrypt    | Memory-hard password hashing             |
| Argon2    | Modern memory-hard password hashing      |

### Symmetric Encryption

#### Block Ciphers

| Algorithm         | Block Size | Key Sizes       | Description                           |
|-------------------|------------|-----------------|---------------------------------------|
| AES               | 128-bit    | 128/192/256-bit | Advanced Encryption Standard          |
| DES               | 64-bit     | 56-bit          | Data Encryption Standard (legacy)     |
| 3DES (Triple DES) | 64-bit     | 112/168-bit     | Triple DES (legacy)                   |
| Blowfish          | 64-bit     | 32-448-bit      | Fast block cipher                     |
| Twofish           | 128-bit    | 128/192/256-bit | AES finalist                          |
| Camellia          | 128-bit    | 128/192/256-bit | Japanese standard                     |
| CAST5 (CAST-128)  | 64-bit     | 40-128-bit      | Legacy cipher                         |
| CAST6 (CAST-256)  | 128-bit    | 128/192/256-bit | AES candidate                         |
| RC5               | 64-bit     | Variable        | Variable rounds                       |
| RC6               | 128-bit    | 128/192/256-bit | AES finalist                          |
| TEA               | 64-bit     | 128-bit         | Tiny Encryption Algorithm             |
| XTEA              | 64-bit     | 128-bit         | Extended TEA                          |
| XXTEA             | 64-bit     | 128-bit         | Corrected Block TEA                   |
| SM4               | 128-bit    | 128-bit         | Chinese national standard             |
| PRESENT           | 64-bit     | 80/128-bit      | Lightweight cipher                    |
| BELT              | 128-bit    | 256-bit         | Belarusian standard                   |
| Simon             | Various    | Various         | NSA lightweight cipher                |
| Playfair          | Digraph    | Keyword-based   | Classical digraph substitution cipher |
| Rail Fence        | Transpose  | Integer key     | Classical transposition cipher        |

#### Block Cipher Modes

| Mode | Description                                          |
|------|------------------------------------------------------|
| ECB  | Electronic Codebook (not recommended)                |
| CBC  | Cipher Block Chaining                                |
| CFB  | Cipher Feedback                                      |
| OFB  | Output Feedback                                      |
| CTR  | Counter mode                                         |
| XTS  | XEX-based tweaked-codebook with ciphertext stealing  |
| EAX  | Authenticated encryption with associated data (AEAD) |
| GCM  | Galois/Counter Mode (AEAD)                           |
| CCM  | Counter with CBC-MAC (AEAD)                          |
| OCB  | Offset Codebook Mode v3 (AEAD, RFC 7253)             |

#### Padding Schemes

| Scheme     | Description        |
|------------|--------------------|
| PKCS7      | PKCS #7 padding    |
| ANSI X.923 | ANSI X9.23 padding |

#### Stream Ciphers

| Algorithm         | Description                             |
|-------------------|-----------------------------------------|
| ChaCha20          | Modern stream cipher                    |
| ChaCha20-Poly1305 | AEAD construction (RFC 8439, TLS 1.3)   |
| Salsa20           | Predecessor to ChaCha20                 |
| RC4               | Legacy stream cipher (deprecated)       |
| SEAL              | Software-optimized encryption algorithm |
| ZUC               | Chinese stream cipher (4G/5G)           |
| Rabbit            | High-performance stream cipher          |
| Trivium           | Hardware-oriented stream cipher         |

#### Classical Ciphers

| Algorithm           | Type                        |
|---------------------|-----------------------------|
| Caesar              | Shift cipher                |
| Vigenere            | Polyalphabetic substitution |
| Atbash              | Monoalphabetic substitution |
| Affine              | Mathematical substitution   |
| ROT13               | Caesar cipher variant       |
| Simple Substitution | Character substitution      |
| Polybius Square     | Fractionating cipher        |

### Asymmetric Encryption

| Algorithm      | Description                                     |
|----------------|-------------------------------------------------|
| RSA            | Rivest-Shamir-Adleman encryption and signatures |
| RSA-PSS        | Probabilistic Signature Scheme                  |
| DSA            | Digital Signature Algorithm                     |
| ECC            | Elliptic Curve Cryptography                     |
| ECDH           | Elliptic Curve Diffie-Hellman                   |
| Ed25519        | Edwards-curve Digital Signature Algorithm       |
| X25519         | Elliptic Curve Diffie-Hellman (Curve25519)      |
| Diffie-Hellman | Key exchange protocol                           |
| ElGamal        | Discrete logarithm-based encryption             |
| Paillier       | Additive homomorphic encryption                 |
| NTRU           | Lattice-based post-quantum encryption           |

### Encoding Schemes

| Encoding         | Description                         |
|------------------|-------------------------------------|
| Base16 (Hex)     | Hexadecimal encoding                |
| Base32           | RFC 4648 Base32                     |
| Base36           | Alphanumeric encoding (0-9, A-Z)    |
| Base58           | Bitcoin-style encoding (no 0/O/I/l) |
| Base62           | Alphanumeric encoding               |
| Base64           | RFC 4648 Base64                     |
| Base85           | ASCII85 encoding                    |
| Base91           | High-density encoding               |
| Base92           | Dense binary-to-text                |
| Hex2Bin          | Binary-hexadecimal conversion       |
| Morse Code       | Telegraph encoding                  |
| URL Encoding     | Percent-encoding                    |
| HTML Entities    | Character entity encoding           |
| Quoted-Printable | MIME email-safe encoding            |
| ROT47            | ASCII shift cipher encoding         |
| ASCII            | ASCII encoding utilities            |

## Security Notice

**IMPORTANT**: This library is intended for educational purposes only.

1. **Not for Production**: These implementations are not optimized for performance and
   have not undergone formal security audits.
2. **Timing Attacks**: Pure Python implementations may be vulnerable to timing attacks
   due to non-constant-time operations.
3. **Deprecated Algorithms**: Some implemented algorithms (MD5, SHA-1, DES, RC4) are
   cryptographically broken or deprecated. They are included for educational and legacy
   compatibility purposes only.
4. **Use Established Libraries**: For production use, please use well-established
   libraries such as:
    - [cryptography](https://cryptography.io/)
    - [pycryptodome](https://www.pycryptodome.org/)
    - Python's built-in `hashlib` and `secrets` modules

## Testing

The project includes comprehensive tests for all implementations:

```bash
# Run all tests with coverage
uv run pytest

# Run specific test file
uv run pytest tests/digest/test_sha.py

# Run without parallelization (for debugging)
uv run pytest -n0

# Run with verbose output
uv run pytest -v
```

Tests validate implementations against reference libraries (`hashlib`, `pycryptodome`,
`cryptography`) to ensure correctness. Coverage target: **95%+**.

## Development

### Code Quality

```bash
# Run linting
uv run ruff check .

# Fix linting issues
uv run ruff check --fix .

# Format code
uv run ruff format .

# Type checking
uv run pyright

# Run all quality checks
uv run poe full
```

### Project Structure

```text
src/crypt/
├── digest/        # Hash algorithms and message authentication
│   ├── CRC/       # CRC8, CRC12, CRC16, CRC32, CRC32C, CRC64
│   ├── HMAC/      # HMAC-MD5, HMAC-SHA1, HMAC-SHA256
│   ├── KDF/       # PBKDF2, scrypt, Argon2
│   ├── MD/        # MD2, MD4, MD5, MD6
│   ├── SHA/       # SHA-0, SHA-1, SHA-2, SHA-3 family
│   └── SHAKE/     # SHAKE128, SHAKE256
├── encode/        # Encoding schemes (Base16/32/36/58/62/64/85/91/92, etc.)
└── encrypt/       # Encryption algorithms
    ├── asymmetric_encrypt/  # RSA, ECC, DSA, ECDH, Ed25519, X25519, ElGamal, Paillier
    ├── end2end_encrypt/     # End-to-end encryption protocols
    └── symmetric_encrypt/   # Secret-key cryptography
        ├── block_cipher/    # AES, DES, Blowfish, Twofish, Camellia, SM4, etc.
        ├── modes/           # ECB, CBC, CFB, OFB, CTR, XTS, EAX
        ├── padding/         # PKCS7, ANSI X.923
        └── stream_cipher/   # ChaCha20, Salsa20, RC4, ZUC, Rabbit, Trivium, etc.
tests/             # Comprehensive test suite
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Code Style**: Follow PEP 8 and use type hints where appropriate
2. **Testing**: Add tests for new algorithms and ensure all tests pass
3. **Documentation**: Include docstrings and comments explaining the algorithm
4. **Security**: Clearly mark any deprecated or broken algorithms
5. **References**: Cite RFCs, papers, or other sources for algorithm implementations

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-algorithm`)
3. Make your changes
4. Run tests and linting (`uv run poe full && uv run pytest`)
5. Commit your changes (`git commit -am 'feat: add new algorithm'`)
6. Push to the branch (`git push origin feature/new-algorithm`)
7. Create a Pull Request

## References

- [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) - Secure Hash
  Standard (SHS)
- [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) - Advanced
  Encryption Standard (AES)
- [RFC 1321](https://tools.ietf.org/html/rfc1321) - The MD5 Message-Digest Algorithm
- [RFC 2104](https://tools.ietf.org/html/rfc2104) - HMAC: Keyed-Hashing for Message
  Authentication
- [RFC 2898](https://tools.ietf.org/html/rfc2898) - PKCS #5: Password-Based Cryptography
- [RFC 4648](https://tools.ietf.org/html/rfc4648) - Base16, Base32, and Base64 Encodings
- [RFC 7748](https://tools.ietf.org/html/rfc7748) - Elliptic Curves for Security
- [RFC 8032](https://tools.ietf.org/html/rfc8032) - Edwards-Curve Digital Signature
  Algorithm

## License

This project is open source. Please see the repository for license information.

## Acknowledgments

This project is inspired by and references implementations from:

- [pycryptodome](https://www.pycryptodome.org/)
- [cryptography](https://cryptography.io/)
- Various academic papers and RFC specifications

---

**Disclaimer**: The authors are not responsible for any misuse of this software. Always
consult with security professionals when implementing cryptography in production
systems.
