# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ⚠️ Changed (breaking — import paths)
- **Package restructured into 9 purpose-based top-level packages.** `digest/`
  and `encrypt/` were split/regrouped; all deep import paths changed:
  - `crypt.digest.{MD,SHA,SHAKE}` → `crypt.hash.{md,sha,shake}`; loose hashes
    (`blake2/3`, `ripemd128/160`, `sm3`, `tiger`, `whirlpool`) moved under
    `crypt.hash/`.
  - `crypt.digest.CRC` + `adler32`/`fnv` → `crypt.checksum/` (+ `crc/`).
  - `crypt.digest.HMAC` + `cmac`/`poly1305`/`siphash` → `crypt.mac/` (+ `hmac/`).
  - `crypt.digest.KDF` + `bcrypt` → `crypt.kdf/`.
  - `crypt.encrypt.symmetric_encrypt` → `crypt.symmetric/`
    (`block_cipher/`, `stream_cipher/`, `modes/`, `padding/`, `aead/`).
  - `crypt.encrypt.asymmetric_encrypt` → `crypt.asymmetric/`.
  - Classical ciphers extracted from `stream_cipher/`+`block_cipher/` into a
    top-level `crypt.classical/`.
  - AEAD (GCM, CCM, ChaCha20-Poly1305) grouped under `crypt.symmetric.aead/`.
  - All CamelCase directories (CRC/HMAC/KDF/MD/SHA/SHAKE) → snake_case (PEP 8).
  - Top-level `__init__.py` files use relative imports (removes fragility from
    the `crypt` package name colliding with the stdlib `crypt` module).
- Algorithm implementations are **unchanged** (only relocated); bit-for-bit
  behavior preserved — 3231 tests pass, 96% coverage.

### Added
- `crypt.classical/` now holds 9 historical ciphers (was 2): Caesar, ROT13,
  Atbash, Affine, Vigenère, Simple Substitution, Polybius, Playfair, Rail Fence.
- Multi-dimensional test verification (`tests/property/`): stdlib oracle
  cross-checks (`hashlib`/`hmac`/`zlib`/`base64`) + Hypothesis property tests
  (round-trip, determinism, involution).
- `pip-audit` dependency-vulnerability gate in the CI `security` job (replaces
  `safety`, which needs interactive login).
- `SECURITY` notices on dangerous primitives (textbook RSA, RC4, ECB, …).
- README rewritten around the new 9-category structure (project tree,
  re-categorized algorithm tables, runnable Quick Start).

### Security
- **DH private key now uses a CSPRNG** (`secrets.randbits`) — previously
  `random.getrandbits` (Mersenne Twister, state recoverable). Critical fix.
- `bandit` B311 moved from a global skip to per-file `# nosec` (only classical
  ciphers suppress it), so real CSPRNG mistakes are detectable again.
- RC4's top-level `Crypto` import moved into `__main__` — the module is now
  importable without `pycryptodome` (restores the pure-Python claim at import).

### Fixed
- README Quick Start examples had stale/wrong API names (`sha256().hex()`,
  `base58_*`, `rsa_*`/`key_size`) — all examples now run and match their output.
- Dead runtime dependency `cryptography` removed (never imported in `src/`).

### Removed
- ~20 unused test dependencies (`moto[all]`, `allure-pytest`, `cosmic-ray`,
  `factory-boy`, `polyfactory`, `syrupy`, `testcontainers`, `pytest-parallel`,
  `time-machine`, `pytest-socket`, …).

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
