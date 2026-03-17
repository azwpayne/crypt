# Block Cipher Modes, Padding Schemes, and SHAKE XOF Design

**Date:** 2026-03-18
**Topic:** Block Cipher Modes, Padding Schemes, and SHAKE XOF Implementation
**Approach:** Approach 2 - Balanced Implementation

---

## Summary

This design adds generic block cipher mode wrappers, standalone padding utilities, and SHAKE extendable-output functions to the existing cryptography library. The implementation follows the project's educational focus with clean, readable Python code.

## Architecture

### Directory Structure

```
src/crypt/encrypt/symmetric_encrypt/modes/
├── __init__.py      # Exports all modes
├── ecb.py           # Electronic Codebook mode
├── cbc.py           # Cipher Block Chaining mode
├── ctr.py           # Counter mode
├── cfb.py           # Cipher Feedback mode
├── ofb.py           # Output Feedback mode
└── xts.py           # XEX-based Tweaked Codebook mode

src/crypt/encrypt/symmetric_encrypt/padding/
├── __init__.py      # Exports all padding schemes
├── pkcs7.py         # PKCS#7 padding (RFC 5652)
└── ansi_x923.py     # ANSI X.923 padding

src/crypt/digest/SHAKE/
├── __init__.py
├── shake128.py      # SHAKE128 XOF (FIPS 202)
└── shake256.py      # SHAKE256 XOF (FIPS 202)
```

### Design Patterns

**Mode Classes:** Each mode is implemented as a class that wraps a block cipher with a consistent interface:
- `__init__(self, encrypt_func, decrypt_func, block_size, iv/nonce)` - Initialize with functions and IV/nonce
- `encrypt(self, plaintext: bytes) -> bytes` - Encrypt data
- `decrypt(self, ciphertext: bytes) -> bytes` - Decrypt data

This function-based approach matches the existing codebase where ciphers expose functions like `aes_ecb_encrypt` rather than class methods.

**Padding Functions:** Standalone functions that work with any block size:
- `pad(data: bytes, block_size: int) -> bytes` - Add padding
- `unpad(data: bytes, block_size: int) -> bytes` - Remove padding

**SHAKE XOF:** Stateful object following hashlib pattern:
- `update(data: bytes) -> None` - Absorb data
- `read(length: int) -> bytes` - Squeeze arbitrary output
- `hexdigest(length: int) -> str` - Get hex output
- `copy() -> SHAKE128/SHAKE256` - Copy the hasher state

## Components

### 1. Block Cipher Modes

All modes work with any block cipher providing `encrypt_block()` and `decrypt_block()` functions, plus a `block_size` value.

Example usage with AES:
```python
from crypt.encrypt.symmetric_encrypt.block_cipher.AES import _encrypt_block, _decrypt_block
from crypt.encrypt.symmetric_encrypt.modes.cbc import CBCMode

cbc = CBCMode(_encrypt_block, _decrypt_block, block_size=16, key=key, iv=iv)
ciphertext = cbc.encrypt(plaintext)
```

#### ECB Mode (`ecb.py`)
- Simple block-by-block encryption
- No IV required
- **Warning:** Not recommended for security (patterns visible)
- Educational implementation with clear warnings

#### CBC Mode (`cbc.py`)
- XORs each plaintext block with previous ciphertext block
- Requires random IV (16 bytes for AES)
- Padding required
- Error propagation: single bit error affects current and next block

#### CTR Mode (`ctr.py`)
- Converts block cipher to stream cipher
- Encrypts counter values, XORs with plaintext
- No padding required
- **Counter configuration:** 96-bit nonce + 32-bit counter (for AES)
  - Counter stored as big-endian in last 4 bytes of block
  - Counter overflow raises `ModeError` (prevents reuse)
- Critical: nonce+counter combination must never repeat

#### CFB Mode (`cfb.py`)
- Similar to stream cipher
- Shift register fed with ciphertext
- Self-synchronizing (errors limited to few blocks)
- **Segment size:** Configurable via constructor
  - `CFBMode(encrypt_func, decrypt_func, block_size, key, iv, segment_size=8)`
  - Default: 8 bits (CFB-8) for compatibility
  - Full block: segment_size = block_size * 8

#### OFB Mode (`ofb.py`)
- Generates keystream independent of plaintext
- No error propagation in ciphertext
- IV must be unique per message

#### XTS Mode (`xts.py`)
- Designed for disk encryption
- **Key interface:** Single key provided, internally split:
  ```python
  XTSMode(encrypt_func, decrypt_func, block_size, key, tweak)
  # key is split: key1 = key[:len(key)//2], key2 = key[len(key)//2:]
  ```
- Tweaks based on sector number (passed per operation, not constructor)
- No padding required (ciphertext stealing for final block)

### 2. Padding Schemes

**Note on PKCS#7:** The existing `AES.py` module already contains PKCS#7 padding functions. The new `padding/pkcs7.py` will:
- Be the canonical shared implementation going forward
- Be compatible with the existing AES functions
- AES module will be updated to import from the shared location

#### PKCS#7 (`pkcs7.py`)
- Most common padding scheme
- Each padding byte contains the padding length
- If data is multiple of block size, adds full block of padding

#### ANSI X.923 (`ansi_x923.py`)
- Last byte contains padding length
- Other padding bytes are zeros
- Less common but sometimes required

### 3. SHAKE XOF

Based on existing Keccak-f[1600] implementation in `sha3_*.py` files.

#### SHAKE128 (`shake128.py`)
- 256-bit capacity, 1344-bit rate
- Arbitrary output length
- Uses `0x1F` domain separator (vs `0x06` for SHA3)

#### SHAKE256 (`shake256.py`)
- 512-bit capacity, 1088-bit rate
- Higher security level than SHAKE128
- Uses same `0x1F` domain separator

## Data Flow

```
Encryption:
Plaintext → [Padding] → Mode Wrapper → Block Cipher → Ciphertext

Decryption:
Ciphertext → Block Cipher → Mode Wrapper → [Unpadding] → Plaintext

SHAKE:
Message → Absorb → Keccak-f → Squeeze → Arbitrary Output
```

## Error Handling

### Custom Exceptions

Defined in respective `__init__.py` files for each module:

**`src/crypt/encrypt/symmetric_encrypt/padding/__init__.py`:**
```python
class PaddingError(ValueError):
    """Invalid padding bytes detected."""
```

**`src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`:**
```python
class ModeError(ValueError):
    """Mode-specific error (e.g., IV reuse, invalid parameters)."""
```

### Error Cases

- **Invalid IV length:** `ValueError` raised with expected vs actual
- **IV/nonce reuse in CTR:** `ModeError` with clear warning
- **Invalid padding:** `PaddingError` with description
- **Ciphertext not aligned:** `ValueError` for block modes

## Testing Strategy

### Unit Tests
Each module includes `test_*()` function with:
- NIST SP 800-38A test vectors where applicable
- Round-trip encryption/decryption tests
- Padding boundary cases (empty, single byte, exact block)
- Error condition tests

### Validation
Tests compare against reference implementations:
- `pycryptodome` for modes and padding
- `hashlib` + `shake_128/256` for SHAKE (Python 3.11+)
- Known answer tests from NIST CAVP

### Test Vectors

**CBC Example (NIST SP 800-38A):**
- Key: `2b7e151628aed2a6abf7158809cf4f3c`
- IV: `000102030405060708090a0b0c0d0e0f`
- Plaintext: `6bc1bee22e409f96e93d7e117393172a`
- Ciphertext: `7649abac8119b246cee98e9b12e9197d`

**SHAKE128 Example:**
- Input: `"abc"`
- Output (first 32 bytes): `5881092dd818bf5cf8a3ddb793c5f6b7...`

## Integration with Existing Code

### Block Cipher Interface

Modes expect callable functions following this signature:

```python
def encrypt_block(block: bytes, expanded_key: list[int], nr: int) -> bytes: ...
def decrypt_block(block: bytes, expanded_key: list[int], nr: int) -> bytes: ...
```

The mode classes handle key expansion internally and pass the expanded key to these functions.

### Compatibility with Existing Ciphers

**AES** (`src/crypt/encrypt/symmetric_encrypt/block_cipher/AES.py`):
- Already has `_encrypt_block()` and `_decrypt_block()` functions
- `block_size = 16`
- Key expansion via `key_expansion()` function
- Mode classes will wrap these internal functions

**DES** (`src/crypt/encrypt/symmetric_encrypt/block_cipher/DES.py`):
- `block_size = 8`
- Will need to expose internal block functions if not already present

**Other ciphers:**
- Blowfish, Twofish, etc. follow similar patterns
- Padding functions work with any block size (8, 16, 32 bytes)

### GCM/CCM Note

The existing `gcm.py` and `ccm.py` files are **AEAD modes** (Authenticated Encryption with Associated Data), not just block cipher modes. They will remain in their current location for backward compatibility. The new `modes/` directory contains **unauthenticated block cipher modes**.

Future work may unify these under a common interface.

## Security Considerations

### ECB Mode
- **Only for educational use**
- Patterns in plaintext visible in ciphertext
- Included for completeness with prominent warnings

### CTR Mode
- **Never reuse nonce+key combination**
- Two messages with same nonce: XOR reveals plaintext
- Implementation tracks nonce usage, raises warning

### XTS Mode
- Two independent keys required (or single key split)
- Tweak must be unique per sector
- Designed specifically for disk encryption

### Padding Oracle
- Unpadding should be constant-time to prevent oracle attacks
- Implementation uses constant-time comparison

## Future Extensions

Potential additions not in scope:
- GCM/GMAC with proper GHASH (current implementations are placeholders)
- CCM with proper formatting function
- OCB mode (patent issues historically, now free)
- ISO/IEC 7816-4 padding

## References

1. NIST SP 800-38A - Recommendation for Block Cipher Modes of Operation
2. NIST SP 800-38B - Recommendation for Block Cipher Modes: CMAC
3. NIST SP 800-38C - Recommendation for Block Cipher Modes: CCM
4. NIST SP 800-38D - Recommendation for Block Cipher Modes: GCM
5. NIST SP 800-38E - Recommendation for Block Cipher Modes: XTS
6. FIPS 202 - SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
7. RFC 5652 - Cryptographic Message Syntax (CMS) - PKCS#7 padding
8. IEEE P1619 - Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices (XTS)

---

**Status:** Design Approved
**Next Step:** Create implementation plan via writing-plans skill
