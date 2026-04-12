# Security Policy

## Educational Purpose Only

**This library is strictly for educational purposes.** The implementations are designed to be readable and understandable, not to be used in production systems.

## Known Limitations

### 1. Timing Side-Channels

Pure Python is inherently vulnerable to timing attacks:

- **Integer operations**: Python's arbitrary-precision integers do not execute in constant time
- **Branching on secrets**: `if` statements that depend on secret data leak timing information
- **Memory access patterns**: Python's object model makes cache-based side-channel resistance impossible

**Mitigations we have implemented:**
- `pkcs7.py` uses `_constant_time_compare` for unpadding verification
- GCM tag verification uses constant-time comparison
- ECB mode emits a `UserWarning` on instantiation

**What we cannot mitigate:**
- General modular exponentiation in RSA/DSA/ElGamal
- Elliptic curve scalar multiplication
- General comparison operations

### 2. Deprecated and Broken Algorithms

The following algorithms are included for historical/educational purposes only and should **never** be used for security:

| Algorithm | Status | Reason |
|-----------|--------|--------|
| MD2       | Broken | Collision vulnerable |
| MD4       | Broken | Collision vulnerable |
| MD5       | Broken | Practical collisions |
| SHA-0     | Broken | Collision vulnerable |
| SHA-1     | Deprecated | Theoretical collision attacks |
| DES       | Broken | 56-bit key, brute-force feasible |
| 3DES      | Deprecated | Sweet32 vulnerability |
| RC4       | Broken | Biases in keystream |

### 3. Randomness

Where randomness is required (RSA key generation, DSA nonces, ECC scalars), we use Python's `secrets` module, which provides cryptographically secure random numbers. However, the algorithms themselves are not suitable for production use regardless.

### 4. Input Validation

All public APIs validate inputs (key sizes, data lengths, etc.) and raise `ValueError` or `TypeError` for invalid inputs. This prevents accidental misuse but does not make the library production-ready.

## Reporting Security Issues

If you discover a security issue in this codebase:

1. **Do not open a public issue** for vulnerabilities
2. Open a **private security advisory** through GitHub, or contact the maintainers directly

Please note: Because this is an educational project, our response prioritizes educational clarity over rapid patching. For production security, use established libraries.

## Recommended Production Alternatives

For real-world cryptography, always use well-audited libraries:

- [cryptography](https://cryptography.io/) — Python's most widely used crypto library
- [pycryptodome](https://www.pycryptodome.org/) — Self-contained alternative
- [libsodium](https://doc.libsodium.org/) via [pynacl](https://pynacl.readthedocs.io/) — Modern, opinionated, hard to misuse
- Python's built-in `hashlib` and `secrets` modules — For basic hashing and randomness

## Security Checklist for Contributors

Before submitting code that handles cryptography:

- [ ] No hardcoded secrets, keys, or passwords
- [ ] All user inputs are validated at API boundaries
- [ ] No silent failure modes for security-critical operations
- [ ] Deprecated algorithms are clearly marked and emit warnings where appropriate
- [ ] Constant-time operations are used wherever feasible in Python
- [ ] Error messages do not leak sensitive data
