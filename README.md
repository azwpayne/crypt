# Crypt

A pure-Python implementation of common cryptographic algorithms for **educational
purposes** — organized by what each algorithm *does* (hash, checksum, MAC, KDF,
classical, symmetric, asymmetric, encoding).

## Overview

This library implements a broad catalog of cryptographic primitives — hash
functions, checksums, message-authentication codes, key-derivation functions,
historical ("classical") ciphers, modern symmetric/asymmetric encryption, and
binary-to-text encodings. The focus is on **clear, readable implementations**
that show how each algorithm works under the hood.

> **Note**: This is an educational project. Implementations are tested against
> reference libraries (`hashlib`, `pycryptodome`) but are **not** optimized for
> production and have not undergone formal security audits. See
> [Security Notice](#security-notice).

## Installation

This project uses [`uv`](https://docs.astral.sh/uv/) for dependency management:

```bash
git clone <repository-url>
cd crypt

uv sync                  # runtime deps only
uv sync --group dev      # + dev tooling (ruff, poethepoet)
uv sync --group test     # + test tooling (pytest, hypothesis, pip-audit, …)
```

### Requirements

- Python >= 3.10
- `uv` (for dependency management)

## Project Structure

Code is organized into top-level packages **by algorithm purpose**, so a learner
can locate any primitive by what it does:

```text
src/crypt/
├── hash/              # Cryptographic hashes (one-way)
│   ├── md/            #   MD2, MD4, MD5, MD6
│   ├── sha/           #   SHA-0/1/2/3, Keccak, SHA-512/224, SHA-512/256
│   ├── shake/         #   SHAKE128, SHAKE256 (extendable-output functions)
│   ├── blake/         #   BLAKE2, BLAKE3
│   ├── ripemd/        #   RIPEMD-128, RIPEMD-160
│   └── sm3, tiger, whirlpool
├── checksum/          # Non-cryptographic integrity checks
│   ├── crc/           #   CRC8/12/16/16-CCITT/32/32C/64
│   └── adler32, fnv
├── mac/               # Message authentication codes
│   ├── hmac/          #   HMAC-MD5/SHA1/SHA256
│   └── cmac, poly1305, siphash
├── kdf/               # Key derivation & password hashing
│   └── pbkdf2, scrypt, argon2, bcrypt
├── classical/         # Historical / pre-computational ciphers (educational only)
│   └── caesar, rot13, vigenere, atbash, affine, polybius,
│       simple_substitution, playfair, rail_fence
├── symmetric/         # Modern symmetric cryptography
│   ├── block_cipher/  #   AES, DES, 3DES, Blowfish, Twofish, Camellia, CAST5/6,
│   │                  #   RC5/6, SM4, TEA/XTEA/XXTEA, Simon, PRESENT, Belt
│   ├── stream_cipher/ #   ChaCha20, Salsa20, RC4, Rabbit, Trivium, SEAL, ZUC
│   ├── modes/         #   ECB, CBC, CFB, OFB, CTR, XTS, EAX, OCB
│   ├── padding/       #   PKCS7, ANSI X.923
│   └── aead/          #   GCM*, CCM*, ChaCha20-Poly1305  (*stub)
├── asymmetric/        # Modern asymmetric cryptography
│   └── rsa, rsa_pss, dsa, ecc, ecdh, x25519, ed25519,
│       diffie_hellman, elgamal, paillier, ntru
├── encode/            # Binary ↔ text encoding
│   └── base16..base92, hex2bin, url, html, quoted_printable, ascii, morse_code, rot47
└── e2e/               # End-to-end encryption composition (stub)
```

## Quick Start

### Hash

```python
from crypt.hash.sha.sha2_256 import sha256

# sha256() returns the hex digest as a string
print(sha256(b"Hello, World!"))
# dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```

### Symmetric Encryption (AES)

```python
from crypt.symmetric.block_cipher.aes import aes_encrypt, aes_decrypt

key = b"0123456789abcdef"  # 16 bytes → AES-128
plaintext = b"Hello, World!!!!"  # must be a whole block (16 bytes)

ciphertext = aes_encrypt(plaintext, key)
print(f"Encrypted: {ciphertext.hex()}")
print(f"Decrypted: {aes_decrypt(ciphertext, key).decode()}")  # Hello, World!!!!
```

### Encoding

```python
from crypt.encode.base64 import base64_encode, base64_decode
from crypt.encode.base58 import encode_base58, decode_base58

data = b"Hello, World!"
print(base64_encode(data))  # SGVsbG8sIFdvcmxkIQ==
print(base64_decode(base64_encode(data)))  # b"Hello, World!"

print(encode_base58(data))  # 72k1xXWG59fYdzSNoA
print(decode_base58(encode_base58(data)))  # b"Hello, World!"
```

### Asymmetric Encryption (RSA)

> ⚠️ The base `rsa` module is **textbook RSA without padding** — educational
> only. See the module's `SECURITY` notice. Use `rsa_pss` for safe signing.

```python
from crypt.asymmetric.rsa import generate_keypair, encrypt, decrypt

public_key, private_key = generate_keypair(bits=2048)

message = b"Hello, RSA!"
ciphertext = encrypt(message, public_key)
print(decrypt(ciphertext, private_key).decode())  # Hello, RSA!
```

## Implemented Algorithms

### Hash (`crypt.hash`)

| Algorithm                   | Description                                   | Security               |
|-----------------------------|-----------------------------------------------|------------------------|
| **MD family** (`md/`)       | MD2, MD4, MD5 (128-bit), MD6                  | MD4/MD5 broken, legacy |
| **SHA-0 / SHA-1** (`sha/`)  | 160-bit                                       | Broken / deprecated    |
| **SHA-2** (`sha/`)          | SHA-224/256/384/512, SHA-512/224, SHA-512/256 | Secure                 |
| **SHA-3 / Keccak** (`sha/`) | SHA3-224/256/384/512, SHA3-KE-*               | Secure                 |
| **SHAKE** (`shake/`)        | SHAKE128, SHAKE256 (XOFs)                     | Secure                 |
| **BLAKE** (`blake/`)        | BLAKE2, BLAKE3                                | Secure                 |
| **RIPEMD** (`ripemd/`)      | RIPEMD-128, RIPEMD-160                        | Legacy                 |
| SM3                         | Chinese national standard hash                | Secure                 |
| Tiger                       | 192-bit hash                                  | Legacy                 |
| Whirlpool                   | 512-bit hash                                  | Legacy                 |

### Checksum (`crypt.checksum`) — non-cryptographic

| Algorithm        | Description                                           |
|------------------|-------------------------------------------------------|
| **CRC** (`crc/`) | CRC8, CRC12, CRC16, CRC16-CCITT, CRC32, CRC32C, CRC64 |
| Adler32          | Checksum                                              |
| FNV              | Non-cryptographic hash                                |

### MAC (`crypt.mac`) — message authentication

| Algorithm          | Description                                         |
|--------------------|-----------------------------------------------------|
| **HMAC** (`hmac/`) | HMAC-MD5, HMAC-SHA1, HMAC-SHA256                    |
| CMAC               | AES-based MAC (NIST SP 800-38B, RFC 4493)           |
| Poly1305           | One-time MAC (paired with a stream cipher for AEAD) |
| SipHash            | Fast keyed hash for hash-table DoS protection       |

### KDF (`crypt.kdf`) — key derivation & password hashing

| Algorithm | Description                                         |
|-----------|-----------------------------------------------------|
| PBKDF2    | Password-Based Key Derivation Function 2 (RFC 2898) |
| scrypt    | Memory-hard password hashing                        |
| Argon2    | Modern memory-hard KDF (PHC winner)                 |
| bcrypt    | Password hashing                                    |

### Classical Ciphers (`crypt.classical`) — educational only

| Cipher              | Type                                |
|---------------------|-------------------------------------|
| Caesar              | Shift substitution                  |
| ROT13               | Caesar with shift 13 (self-inverse) |
| Atbash              | Reverse-alphabet substitution       |
| Affine              | Affine substitution                 |
| Vigenère            | Poly-alphabetic substitution        |
| Simple Substitution | Arbitrary alphabet permutation      |
| Polybius            | Coordinate substitution             |
| Playfair            | Digraph substitution                |
| Rail Fence          | Transposition                       |

### Symmetric (`crypt.symmetric`)

**Block ciphers** (`block_cipher/`)

| Algorithm          | Block      | Key sizes       | Security               |
|--------------------|------------|-----------------|------------------------|
| AES                | 128-bit    | 128/192/256-bit | Secure                 |
| DES                | 64-bit     | 56-bit          | Broken, legacy         |
| 3DES               | 64-bit     | 112/168-bit     | Deprecated             |
| Blowfish           | 64-bit     | 32–448-bit      | Legacy                 |
| Twofish            | 128-bit    | 128/192/256-bit | Secure                 |
| Camellia           | 128-bit    | 128/192/256-bit | Secure                 |
| CAST5 / CAST6      | 64/128-bit | 40–256-bit      | Legacy / AES candidate |
| RC5 / RC6          | 64/128-bit | Variable        | Legacy / AES finalist  |
| SM4                | 128-bit    | 128-bit         | Secure                 |
| TEA / XTEA / XXTEA | 64/128-bit | 128-bit         | Legacy                 |
| Simon              | Various    | Various         | NSA lightweight        |
| PRESENT            | 64-bit     | 80/128-bit      | Lightweight            |
| Belt               | 128-bit    | 256-bit         | Belarusian standard    |

**Modes** (`modes/`)

| Mode | Description                                  | Authenticated |
|------|----------------------------------------------|---------------|
| ECB  | Electronic Codebook (educational only)       | No            |
| CBC  | Cipher Block Chaining                        | No            |
| CFB  | Cipher Feedback                              | No            |
| OFB  | Output Feedback                              | No            |
| CTR  | Counter                                      | No            |
| XTS  | XEX-based tweaked-codebook (disk encryption) | No            |
| EAX  | AEAD with associated data                    | Yes           |
| OCB  | Offset Codebook v3 (RFC 7253)                | Yes           |

**AEAD** (`aead/`)

| Algorithm         | Note                                                       |
|-------------------|------------------------------------------------------------|
| ChaCha20-Poly1305 | AEAD (RFC 8439, TLS 1.3)                                   |
| GCM               | **Stub** — uses SHA-256 keystream, not real CTR. Dev only. |
| CCM               | **Stub** — same caveat as GCM.                             |

**Stream ciphers** (`stream_cipher/`)

| Algorithm | Description                     | Security |
|-----------|---------------------------------|----------|
| ChaCha20  | Modern stream cipher            | Secure   |
| Salsa20   | Predecessor to ChaCha20         | Secure   |
| RC4       | Legacy stream cipher            | Broken   |
| Rabbit    | High-performance stream cipher  | Secure   |
| Trivium   | Hardware-oriented stream cipher | Secure   |
| SEAL      | Software-optimized encryption   | Legacy   |
| ZUC       | **Stub** (placeholder)          | —        |

**Padding** (`padding/`): PKCS7, ANSI X.923

### Asymmetric (`crypt.asymmetric`)

| Algorithm      | Description                                         |
|----------------|-----------------------------------------------------|
| RSA            | Textbook RSA (no padding — see SECURITY notice)     |
| RSA-PSS        | Probabilistic Signature Scheme (safe signing)       |
| DSA            | Digital Signature Algorithm                         |
| ECC            | Elliptic Curve Cryptography                         |
| ECDH           | Elliptic Curve Diffie-Hellman                       |
| X25519         | ECDH on Curve25519                                  |
| Ed25519        | Edwards-curve signatures                            |
| Diffie-Hellman | Key exchange (uses CSPRNG for the private exponent) |
| ElGamal        | Discrete-log encryption                             |
| Paillier       | Additive homomorphic encryption                     |
| NTRU           | Lattice-based post-quantum encryption               |

### Encoding (`crypt.encode`)

| Encoding                      | Description                                 |
|-------------------------------|---------------------------------------------|
| Base16 (Hex), Hex2Bin         | Hexadecimal                                 |
| Base32                        | RFC 4648                                    |
| Base36 / Base58 / Base62      | Alphanumeric / Bitcoin-style / alphanumeric |
| Base64                        | RFC 4648                                    |
| Base85 / Base91 / Base92      | High-density binary-to-text                 |
| URL / HTML / Quoted-Printable | Percent / entity / MIME-safe                |
| Morse Code / ROT47 / ASCII    | Telegraph / ASCII-shift / ASCII utilities   |

## Security Notice

**This library is for educational purposes only.**

1. **Not for production** — implementations are unoptimized and unaudited.
2. **Timing attacks** — pure-Python is generally not constant-time.
3. **Dangerous primitives are labeled in place** — each module that implements a
   broken/insecure-by-design primitive (textbook RSA, RC4, ECB, MD5/SHA-1, DES)
   carries a `SECURITY`/warning notice in its docstring. Read it before use.
4. **Stubs** — GCM, CCM, and ZUC are stubs; do not use them for real crypto.
5. **Use established libraries for production
   **: [cryptography](https://cryptography.io/),
   [pycryptodome](https://www.pycryptodome.org/), or Python's built-in `hashlib`
   / `hmac` / `secrets`.

See [SECURITY.md](.github/SECURITY.md) for detailed considerations.

## Testing

Tests live under `tests/` mirroring the source structure, plus a `tests/property/`
suite for multi-dimensional verification:

```bash
uv run --group test python -m pytest                 # full suite (parallel + coverage)
uv run --group test python -m pytest tests/hash/sha/ # a specific area
uv run --group test python -m pytest -n0             # serial (debugging)
```

Coverage gate: **90%+** (current: 96%). Tests validate against `hashlib` /
`pycryptodome` known-answer vectors **and** via:

- **Stdlib oracle cross-checks** (`tests/property/`) — our output vs `hashlib`,
  `hmac`, `zlib`, `base64` across arbitrary inputs.
- **Hypothesis property tests** — round-trip, determinism, and involution
  invariants over generated inputs.

Quality gates (run as CI jobs, not inside pytest): `ruff`, `mypy`, `bandit`
(code-level), `pip-audit` (dependency-level).

## Development

```bash
uv run ruff check .          # lint
uv run ruff format .         # format
uv run mypy src/             # type check
uv run bandit -r src/ -c pyproject.toml   # code security
uv run pip-audit             # dependency security
uv run poe full              # clean + format
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](.github/CONTRIBUTING.md)
for guidelines.

## References

- [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) — SHA
- [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) — AES
- [RFC 1321](https://tools.ietf.org/html/rfc1321) — MD5
- [RFC 2104](https://tools.ietf.org/html/rfc2104) — HMAC
- [RFC 2898](https://tools.ietf.org/html/rfc2898) — PKCS #5 (PBKDF2)
- [RFC 4648](https://tools.ietf.org/html/rfc4648) — Base16/32/64
- [RFC 7748](https://tools.ietf.org/html/rfc7748) — Curve25519 / Curve448
- [RFC 8032](https://tools.ietf.org/html/rfc8032) — EdDSA (Ed25519)
- [RFC 8439](https://tools.ietf.org/html/rfc8439) — ChaCha20-Poly1305

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Inspired by and cross-checked against [pycryptodome](https://www.pycryptodome.org/),
[cryptography](https://cryptography.io/), Python's `hashlib`/`hmac`/`secrets`,
and the RFC/FIPS standards above.

---

**Disclaimer**: The authors are not responsible for misuse. Always consult
security professionals for production cryptography.
