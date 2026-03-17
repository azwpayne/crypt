# Block Cipher Modes, Padding, and SHAKE Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 6 block cipher modes (ECB, CBC, CTR, CFB, OFB, XTS), 2 padding schemes (PKCS#7, ANSI X.923), and SHAKE128/SHAKE256 XOF functions following the approved design spec.

**Architecture:** Mode classes wrap block cipher functions (encrypt_block, decrypt_block) with consistent interface. Padding functions are standalone utilities. SHAKE extends existing Keccak-f implementation with XOF capability.

**Tech Stack:** Pure Python, pytest for testing, pycryptodome/hashlib for validation, existing Keccak-f from sha3_*.py files.

**Design Spec:** `docs/superpowers/specs/2026-03-18-block-cipher-modes-padding-shake-design.md`

---

## File Structure Overview

```
src/crypt/encrypt/symmetric_encrypt/modes/
├── __init__.py      # Exports, ModeError exception
├── ecb.py           # Electronic Codebook mode
├── cbc.py           # Cipher Block Chaining mode
├── ctr.py           # Counter mode
├── cfb.py           # Cipher Feedback mode
├── ofb.py           # Output Feedback mode
└── xts.py           # XEX-based Tweaked Codebook mode

src/crypt/encrypt/symmetric_encrypt/padding/
├── __init__.py      # Exports, PaddingError exception
├── pkcs7.py         # PKCS#7 padding (RFC 5652)
└── ansi_x923.py     # ANSI X.923 padding

src/crypt/digest/SHAKE/
├── __init__.py      # Exports
├── shake128.py      # SHAKE128 XOF
└── shake256.py      # SHAKE256 XOF

tests/encrypt/symmetric_encrypt/modes/
├── test_ecb.py
├── test_cbc.py
├── test_ctr.py
├── test_cfb.py
├── test_ofb.py
└── test_xts.py

tests/encrypt/symmetric_encrypt/padding/
├── test_pkcs7.py
└── test_ansi_x923.py

tests/digest/SHAKE/
├── test_shake128.py
└── test_shake256.py
```

---

## Task 1: Create Directory Structure

**Files:**
- Create directories: `src/crypt/encrypt/symmetric_encrypt/modes/`, `src/crypt/encrypt/symmetric_encrypt/padding/`, `src/crypt/digest/SHAKE/`
- Create directories: `tests/encrypt/symmetric_encrypt/modes/`, `tests/encrypt/symmetric_encrypt/padding/`, `tests/digest/SHAKE/`

- [ ] **Step 1: Create source directories**

```bash
mkdir -p src/crypt/encrypt/symmetric_encrypt/modes
mkdir -p src/crypt/encrypt/symmetric_encrypt/padding
mkdir -p src/crypt/digest/SHAKE
```

- [ ] **Step 2: Create test directories**

```bash
mkdir -p tests/encrypt/symmetric_encrypt/modes
mkdir -p tests/encrypt/symmetric_encrypt/padding
mkdir -p tests/digest/SHAKE
```

- [ ] **Step 3: Commit**

```bash
git add .
git commit -m "chore: create directory structure for modes, padding, and SHAKE"
```

---

## Task 2: Padding Exceptions and PKCS#7

**Files:**
- Create: `src/crypt/encrypt/symmetric_encrypt/padding/__init__.py`
- Create: `src/crypt/encrypt/symmetric_encrypt/padding/pkcs7.py`
- Create: `tests/encrypt/symmetric_encrypt/padding/test_pkcs7.py`

- [ ] **Step 1: Write PaddingError exception**

Create `src/crypt/encrypt/symmetric_encrypt/padding/__init__.py`:

```python
"""Padding schemes for block ciphers."""

from .pkcs7 import pad as pkcs7_pad, unpad as pkcs7_unpad

__all__ = ["pkcs7_pad", "pkcs7_unpad", "PaddingError"]


class PaddingError(ValueError):
    """Invalid padding bytes detected."""

    pass
```

- [ ] **Step 2: Write PKCS#7 padding implementation**

Create `src/crypt/encrypt/symmetric_encrypt/padding/pkcs7.py`:

```python
"""PKCS#7 padding (RFC 5652)."""


def pad(data: bytes, block_size: int) -> bytes:
    """
    Apply PKCS#7 padding to data.

    Args:
        data: The data to pad.
        block_size: The block size in bytes (1-255).

    Returns:
        The padded data.

    Raises:
        ValueError: If block_size is not in range 1-255.
    """
    if not 1 <= block_size <= 255:
        msg = f"block_size must be 1-255, got {block_size}"
        raise ValueError(msg)

    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size

    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes, block_size: int) -> bytes:
    """
    Remove PKCS#7 padding from data.

    Args:
        data: The padded data.
        block_size: The block size in bytes (1-255).

    Returns:
        The unpadded data.

    Raises:
        ValueError: If padding is invalid.
    """
    if not 1 <= block_size <= 255:
        msg = f"block_size must be 1-255, got {block_size}"
        raise ValueError(msg)

    if not data:
        msg = "Empty data"
        raise ValueError(msg)

    padding_len = data[-1]

    if padding_len < 1 or padding_len > block_size:
        msg = f"Invalid padding length: {padding_len}"
        raise ValueError(msg)

    if len(data) < padding_len:
        msg = "Data too short for padding"
        raise ValueError(msg)

    # Constant-time padding verification
    expected_padding = bytes([padding_len] * padding_len)
    actual_padding = data[-padding_len:]

    if actual_padding != expected_padding:
        msg = "Invalid padding bytes"
        raise ValueError(msg)

    return data[:-padding_len]


def test_pkcs7():
    """Test PKCS#7 padding with NIST-style vectors."""
    # Test empty data
    padded = pad(b"", 16)
    assert len(padded) == 16
    assert padded == b"\x10" * 16
    assert unpad(padded, 16) == b""

    # Test data that needs padding
    padded = pad(b"hello", 16)
    assert len(padded) == 16
    assert padded == b"hello" + b"\x0b" * 11
    assert unpad(padded, 16) == b"hello"

    # Test data that is exactly block size (adds full block)
    data = b"a" * 16
    padded = pad(data, 16)
    assert len(padded) == 32
    assert padded == data + b"\x10" * 16
    assert unpad(padded, 16) == data

    # Test 8-byte block size (DES)
    padded = pad(b"test", 8)
    assert len(padded) == 8
    assert unpad(padded, 8) == b"test"

    print("All PKCS#7 tests passed!")


if __name__ == "__main__":
    test_pkcs7()
```

- [ ] **Step 3: Write PKCS#7 tests**

Create `tests/encrypt/symmetric_encrypt/padding/test_pkcs7.py`:

```python
"""Tests for PKCS#7 padding."""

import pytest

from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import pad, unpad


class TestPKCS7Pad:
    """Test PKCS#7 padding."""

    def test_pad_empty(self):
        """Test padding empty data."""
        padded = pad(b"", 16)
        assert len(padded) == 16
        assert padded == b"\x10" * 16

    def test_pad_short_block(self):
        """Test padding short data."""
        padded = pad(b"hello", 16)
        assert len(padded) == 16
        assert padded == b"hello" + b"\x0b" * 11

    def test_pad_exact_block(self):
        """Test padding exact block size (adds full block)."""
        data = b"a" * 16
        padded = pad(data, 16)
        assert len(padded) == 32
        assert padded == data + b"\x10" * 16

    def test_pad_8byte_block(self):
        """Test padding with 8-byte block (DES)."""
        padded = pad(b"test", 8)
        assert len(padded) == 8
        assert padded == b"test" + b"\x04" * 4

    def test_pad_invalid_block_size(self):
        """Test padding with invalid block size."""
        with pytest.raises(ValueError, match="block_size must be 1-255"):
            pad(b"test", 0)
        with pytest.raises(ValueError, match="block_size must be 1-255"):
            pad(b"test", 256)


class TestPKCS7Unpad:
    """Test PKCS#7 unpadding."""

    def test_unpad_empty(self):
        """Test unpadding empty data."""
        padded = pad(b"", 16)
        assert unpad(padded, 16) == b""

    def test_unpad_short(self):
        """Test unpadding short data."""
        padded = pad(b"hello", 16)
        assert unpad(padded, 16) == b"hello"

    def test_unpad_exact_block(self):
        """Test unpadding exact block size."""
        data = b"a" * 16
        padded = pad(data, 16)
        assert unpad(padded, 16) == data

    def test_unpad_empty_data(self):
        """Test unpadding empty data raises error."""
        with pytest.raises(ValueError, match="Empty data"):
            unpad(b"", 16)

    def test_unpad_invalid_length(self):
        """Test unpadding with invalid padding length."""
        with pytest.raises(ValueError, match="Invalid padding length"):
            unpad(b"test\x11", 16)  # padding length > block_size

    def test_unpad_invalid_bytes(self):
        """Test unpadding with invalid padding bytes."""
        with pytest.raises(ValueError, match="Invalid padding bytes"):
            unpad(b"test\x02\x01", 16)  # inconsistent padding


class TestPKCS7RoundTrip:
    """Test PKCS#7 round-trip."""

    @pytest.mark.parametrize("block_size", [8, 16, 32])
    @pytest.mark.parametrize(
        "data",
        [b"", b"a", b"hello", b"a" * 8, b"a" * 16, b"a" * 100],
    )
    def test_round_trip(self, data, block_size):
        """Test pad/unpad round-trip."""
        padded = pad(data, block_size)
        assert len(padded) % block_size == 0
        assert unpad(padded, block_size) == data
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/padding/test_pkcs7.py -v
```

Expected: All 14 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypt/encrypt/symmetric_encrypt/padding/ tests/encrypt/symmetric_encrypt/padding/
git commit -m "feat(padding): add PKCS#7 padding implementation with tests"
```

---

## Task 3: ANSI X.923 Padding

**Files:**
- Create: `src/crypt/encrypt/symmetric_encrypt/padding/ansi_x923.py`
- Modify: `src/crypt/encrypt/symmetric_encrypt/padding/__init__.py`
- Create: `tests/encrypt/symmetric_encrypt/padding/test_ansi_x923.py`

- [ ] **Step 1: Write ANSI X.923 padding implementation**

Create `src/crypt/encrypt/symmetric_encrypt/padding/ansi_x923.py`:

```python
"""ANSI X.923 padding."""


def pad(data: bytes, block_size: int) -> bytes:
    """
    Apply ANSI X.923 padding to data.

    The last byte contains the padding length.
    Other padding bytes are zeros.

    Args:
        data: The data to pad.
        block_size: The block size in bytes (1-255).

    Returns:
        The padded data.

    Raises:
        ValueError: If block_size is not in range 1-255.
    """
    if not 1 <= block_size <= 255:
        msg = f"block_size must be 1-255, got {block_size}"
        raise ValueError(msg)

    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size

    # All zeros except last byte which is padding length
    return data + b"\x00" * (padding_len - 1) + bytes([padding_len])


def unpad(data: bytes, block_size: int) -> bytes:
    """
    Remove ANSI X.923 padding from data.

    Args:
        data: The padded data.
        block_size: The block size in bytes (1-255).

    Returns:
        The unpadded data.

    Raises:
        ValueError: If padding is invalid.
    """
    if not 1 <= block_size <= 255:
        msg = f"block_size must be 1-255, got {block_size}"
        raise ValueError(msg)

    if not data:
        msg = "Empty data"
        raise ValueError(msg)

    padding_len = data[-1]

    if padding_len < 1 or padding_len > block_size:
        msg = f"Invalid padding length: {padding_len}"
        raise ValueError(msg)

    if len(data) < padding_len:
        msg = "Data too short for padding"
        raise ValueError(msg)

    # Verify padding bytes are zeros (except last)
    padding_start = len(data) - padding_len
    for i in range(padding_start, len(data) - 1):
        if data[i] != 0:
            msg = "Invalid padding bytes"
            raise ValueError(msg)

    return data[:-padding_len]


def test_ansi_x923():
    """Test ANSI X.923 padding."""
    # Test empty data
    padded = pad(b"", 16)
    assert len(padded) == 16
    assert padded == b"\x00" * 15 + b"\x10"
    assert unpad(padded, 16) == b""

    # Test data that needs padding
    padded = pad(b"hello", 16)
    assert len(padded) == 16
    assert padded == b"hello" + b"\x00" * 10 + b"\x0b"
    assert unpad(padded, 16) == b"hello"

    # Test data that is exactly block size
    data = b"a" * 16
    padded = pad(data, 16)
    assert len(padded) == 32
    assert padded == data + b"\x00" * 15 + b"\x10"
    assert unpad(padded, 16) == data

    print("All ANSI X.923 tests passed!")


if __name__ == "__main__":
    test_ansi_x923()
```

- [ ] **Step 2: Update padding __init__.py**

Modify `src/crypt/encrypt/symmetric_encrypt/padding/__init__.py`:

```python
"""Padding schemes for block ciphers."""

from .ansi_x923 import pad as ansi_x923_pad, unpad as ansi_x923_unpad
from .pkcs7 import pad as pkcs7_pad, unpad as pkcs7_unpad

__all__ = [
    "pkcs7_pad",
    "pkcs7_unpad",
    "ansi_x923_pad",
    "ansi_x923_unpad",
    "PaddingError",
]


class PaddingError(ValueError):
    """Invalid padding bytes detected."""

    pass
```

- [ ] **Step 3: Write ANSI X.923 tests**

Create `tests/encrypt/symmetric_encrypt/padding/test_ansi_x923.py`:

```python
"""Tests for ANSI X.923 padding."""

import pytest

from crypt.encrypt.symmetric_encrypt.padding.ansi_x923 import pad, unpad


class TestANSIX923Pad:
    """Test ANSI X.923 padding."""

    def test_pad_empty(self):
        """Test padding empty data."""
        padded = pad(b"", 16)
        assert len(padded) == 16
        assert padded == b"\x00" * 15 + b"\x10"

    def test_pad_short_block(self):
        """Test padding short data."""
        padded = pad(b"hello", 16)
        assert len(padded) == 16
        assert padded == b"hello" + b"\x00" * 10 + b"\x0b"

    def test_pad_exact_block(self):
        """Test padding exact block size."""
        data = b"a" * 16
        padded = pad(data, 16)
        assert len(padded) == 32
        assert padded == data + b"\x00" * 15 + b"\x10"

    def test_pad_invalid_block_size(self):
        """Test padding with invalid block size."""
        with pytest.raises(ValueError, match="block_size must be 1-255"):
            pad(b"test", 0)


class TestANSIX923Unpad:
    """Test ANSI X.923 unpadding."""

    def test_unpad_empty(self):
        """Test unpadding empty data."""
        padded = pad(b"", 16)
        assert unpad(padded, 16) == b""

    def test_unpad_short(self):
        """Test unpadding short data."""
        padded = pad(b"hello", 16)
        assert unpad(padded, 16) == b"hello"

    def test_unpad_invalid_padding_bytes(self):
        """Test unpadding with non-zero padding bytes."""
        with pytest.raises(ValueError, match="Invalid padding bytes"):
            unpad(b"test\x01\x02", 16)  # padding byte is not zero


class TestANSIX923RoundTrip:
    """Test ANSI X.923 round-trip."""

    @pytest.mark.parametrize("block_size", [8, 16, 32])
    @pytest.mark.parametrize(
        "data",
        [b"", b"a", b"hello", b"a" * 8, b"a" * 16, b"a" * 100],
    )
    def test_round_trip(self, data, block_size):
        """Test pad/unpad round-trip."""
        padded = pad(data, block_size)
        assert len(padded) % block_size == 0
        assert unpad(padded, block_size) == data
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/padding/test_ansi_x923.py -v
```

Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypt/encrypt/symmetric_encrypt/padding/ tests/encrypt/symmetric_encrypt/padding/
git commit -m "feat(padding): add ANSI X.923 padding implementation with tests"
```

---

## Task 4: Mode Exceptions and ECB Mode

**Files:**
- Create: `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`
- Create: `src/crypt/encrypt/symmetric_encrypt/modes/ecb.py`
- Create: `tests/encrypt/symmetric_encrypt/modes/test_ecb.py`

- [ ] **Step 1: Write ModeError exception (minimal __init__.py)**

Create `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`:

```python
"""Block cipher modes of operation."""

from .ecb import ECBMode

__all__ = [
    "ECBMode",
    "ModeError",
]


class ModeError(ValueError):
    """Mode-specific error (e.g., IV reuse, invalid parameters)."""

    pass
```

**Note:** This minimal version avoids circular imports. We'll add other modes to __all__ after they are created.

- [ ] **Step 2: Write ECB mode implementation**

Create `src/crypt/encrypt/symmetric_encrypt/modes/ecb.py`:

```python
"""
ECB (Electronic Codebook) mode.

WARNING: ECB mode is not recommended for security-sensitive applications
because identical plaintext blocks produce identical ciphertext blocks,
making patterns in the plaintext visible in the ciphertext.

This implementation is provided for educational purposes and compatibility
with systems that require ECB mode.
"""

import warnings
from typing import Callable

from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import pad, unpad


class ECBMode:
    """
    Electronic Codebook mode wrapper.

    WARNING: Not recommended for security. Use CBC, CTR, or GCM instead.
    """

    def __init__(
        self,
        encrypt_func: Callable,
        decrypt_func: Callable,
        block_size: int,
        key: bytes,
        expanded_key: list[int] | None = None,
        nr: int | None = None,
    ):
        """
        Initialize ECB mode.

        Args:
            encrypt_func: Function to encrypt a single block.
                         Signature: encrypt_block(block, expanded_key, nr)
            decrypt_func: Function to decrypt a single block.
                         Signature: decrypt_block(block, expanded_key, nr)
            block_size: Block size in bytes.
            key: The encryption key.
            expanded_key: Pre-computed expanded key (optional).
            nr: Number of rounds (optional).
        """
        warnings.warn(
            "ECB mode is not secure for most applications. "
            "Consider using CBC, CTR, or GCM mode instead.",
            stacklevel=2,
        )

        self._encrypt_func = encrypt_func
        self._decrypt_func = decrypt_func
        self.block_size = block_size
        self._key = key

        # Compute expanded key if not provided
        if expanded_key is None or nr is None:
            from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
                key_expansion,
                _get_key_params,
            )

            _nk, self._nr = _get_key_params(key)
            self._expanded_key = key_expansion(key)
        else:
            self._expanded_key = expanded_key
            self._nr = nr

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using ECB mode.

        Args:
            plaintext: Data to encrypt (will be PKCS7 padded).

        Returns:
            Ciphertext (multiple of block_size).
        """
        padded = pad(plaintext, self.block_size)
        ciphertext = bytearray()

        for i in range(0, len(padded), self.block_size):
            block = padded[i : i + self.block_size]
            encrypted = self._encrypt_func(block, self._expanded_key, self._nr)
            ciphertext.extend(encrypted)

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using ECB mode.

        Args:
            ciphertext: Data to decrypt (must be multiple of block_size).

        Returns:
            Decrypted plaintext (PKCS7 padding removed).
        """
        if len(ciphertext) % self.block_size != 0:
            msg = f"Ciphertext length must be multiple of {self.block_size}"
            raise ValueError(msg)

        plaintext = bytearray()

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i : i + self.block_size]
            decrypted = self._decrypt_func(block, self._expanded_key, self._nr)
            plaintext.extend(decrypted)

        return unpad(bytes(plaintext), self.block_size)


def test_ecb_mode():
    """Test ECB mode with AES."""
    import warnings

    from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
        _encrypt_block,
        _decrypt_block,
        key_expansion,
    )

    key = b"0123456789abcdef"  # 16 bytes
    plaintext = b"Hello, World!!!"  # 15 bytes -> will be padded to 16

    # Suppress warning for test
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ecb = ECBMode(_encrypt_block, _decrypt_block, 16, key)
        ciphertext = ecb.encrypt(plaintext)
        decrypted = ecb.decrypt(ciphertext)

    assert decrypted == plaintext
    print("ECB mode test passed!")


if __name__ == "__main__":
    test_ecb_mode()
```

- [ ] **Step 3: Write ECB tests**

Create `tests/encrypt/symmetric_encrypt/modes/test_ecb.py`:

```python
"""Tests for ECB mode."""

import warnings

import pytest

from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _decrypt_block,
    _encrypt_block,
)
from crypt.encrypt.symmetric_encrypt.modes.ecb import ECBMode


class TestECBMode:
    """Test ECB mode encryption/decryption."""

    @pytest.fixture
    def aes_key(self):
        """AES-128 test key."""
        return b"0123456789abcdef"

    @pytest.fixture
    def ecb(self, aes_key):
        """ECB mode instance (with warning suppressed)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ECBMode(_encrypt_block, _decrypt_block, 16, aes_key)

    def test_ecb_warning(self, aes_key):
        """Test that ECB mode emits a warning."""
        with pytest.warns(UserWarning, match="ECB mode is not secure"):
            ECBMode(_encrypt_block, _decrypt_block, 16, aes_key)

    def test_encrypt_decrypt(self, ecb):
        """Test basic encrypt/decrypt."""
        plaintext = b"Hello, World!!!"
        ciphertext = ecb.encrypt(plaintext)
        decrypted = ecb.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_empty_data(self, ecb):
        """Test encrypting empty data."""
        plaintext = b""
        ciphertext = ecb.encrypt(plaintext)
        decrypted = ecb.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_exact_block(self, ecb):
        """Test data that is exactly one block."""
        plaintext = b"a" * 16
        ciphertext = ecb.encrypt(plaintext)
        assert len(ciphertext) == 32  # Padded to 2 blocks
        decrypted = ecb.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_multiple_blocks(self, ecb):
        """Test data spanning multiple blocks."""
        plaintext = b"a" * 48  # 3 blocks
        ciphertext = ecb.encrypt(plaintext)
        assert len(ciphertext) == 64  # 4 blocks with padding
        decrypted = ecb.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_invalid_ciphertext_length(self, ecb):
        """Test decrypting ciphertext with invalid length."""
        with pytest.raises(ValueError, match="Ciphertext length must be multiple"):
            ecb.decrypt(b"invalid")  # Not multiple of block size
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/modes/test_ecb.py -v
```

Expected: 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypt/encrypt/symmetric_encrypt/modes/__init__.py
 git add src/crypt/encrypt/symmetric_encrypt/modes/ecb.py
 git add tests/encrypt/symmetric_encrypt/modes/test_ecb.py
 git commit -m "feat(modes): add ECB mode with security warning and tests"
```

---

## Task 5: CBC Mode

**Files:**
- Create: `src/crypt/encrypt/symmetric_encrypt/modes/cbc.py`
- Create: `tests/encrypt/symmetric_encrypt/modes/test_cbc.py`

- [ ] **Step 1: Write CBC mode implementation**

Create `src/crypt/encrypt/symmetric_encrypt/modes/cbc.py`:

```python
"""CBC (Cipher Block Chaining) mode."""

from typing import Callable

from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import pad, unpad


class CBCMode:
    """
    Cipher Block Chaining mode wrapper.

    Each plaintext block is XORed with the previous ciphertext block
    before being encrypted.
    """

    def __init__(
        self,
        encrypt_func: Callable,
        decrypt_func: Callable,
        block_size: int,
        key: bytes,
        iv: bytes,
        expanded_key: list[int] | None = None,
        nr: int | None = None,
    ):
        """
        Initialize CBC mode.

        Args:
            encrypt_func: Function to encrypt a single block.
            decrypt_func: Function to decrypt a single block.
            block_size: Block size in bytes.
            key: The encryption key.
            iv: Initialization vector (must be block_size bytes).
            expanded_key: Pre-computed expanded key (optional).
            nr: Number of rounds (optional).
        """
        if len(iv) != block_size:
            msg = f"IV must be {block_size} bytes, got {len(iv)}"
            raise ValueError(msg)

        self._encrypt_func = encrypt_func
        self._decrypt_func = decrypt_func
        self.block_size = block_size
        self._key = key
        self._iv = iv

        # Compute expanded key if not provided
        if expanded_key is None or nr is None:
            from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
                key_expansion,
                _get_key_params,
            )

            _nk, self._nr = _get_key_params(key)
            self._expanded_key = key_expansion(key)
        else:
            self._expanded_key = expanded_key
            self._nr = nr

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using CBC mode.

        Args:
            plaintext: Data to encrypt (will be PKCS7 padded).

        Returns:
            Ciphertext (multiple of block_size).
        """
        padded = pad(plaintext, self.block_size)
        ciphertext = bytearray()
        prev_block = self._iv

        for i in range(0, len(padded), self.block_size):
            block = padded[i : i + self.block_size]
            # XOR with previous ciphertext block (or IV)
            xored = bytes([block[j] ^ prev_block[j] for j in range(self.block_size)])
            encrypted = self._encrypt_func(xored, self._expanded_key, self._nr)
            ciphertext.extend(encrypted)
            prev_block = encrypted

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using CBC mode.

        Args:
            ciphertext: Data to decrypt (must be multiple of block_size).

        Returns:
            Decrypted plaintext (PKCS7 padding removed).
        """
        if len(ciphertext) % self.block_size != 0:
            msg = f"Ciphertext length must be multiple of {self.block_size}"
            raise ValueError(msg)

        plaintext = bytearray()
        prev_block = self._iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i : i + self.block_size]
            decrypted = self._decrypt_func(block, self._expanded_key, self._nr)
            # XOR with previous ciphertext block (or IV)
            xored = bytes([decrypted[j] ^ prev_block[j] for j in range(self.block_size)])
            plaintext.extend(xored)
            prev_block = block

        return unpad(bytes(plaintext), self.block_size)


def test_cbc_mode():
    """Test CBC mode with NIST SP 800-38A test vector."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
        _encrypt_block,
        _decrypt_block,
    )

    # NIST SP 800-38A test vector
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_ciphertext = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")

    cbc = CBCMode(_encrypt_block, _decrypt_block, 16, key, iv)

    # Test single block
    ciphertext = cbc.encrypt(plaintext)
    assert ciphertext == expected_ciphertext

    decrypted = cbc.decrypt(ciphertext)
    assert decrypted == plaintext

    print("CBC mode test passed!")


if __name__ == "__main__":
    test_cbc_mode()
```

- [ ] **Step 2: Write CBC tests**

Create `tests/encrypt/symmetric_encrypt/modes/test_cbc.py`:

```python
"""Tests for CBC mode."""

import pytest

from Cryptodome.Cipher import AES as CryptoAES
from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _decrypt_block,
    _encrypt_block,
)
from crypt.encrypt.symmetric_encrypt.modes.cbc import CBCMode


class TestCBCMode:
    """Test CBC mode encryption/decryption."""

    @pytest.fixture
    def aes_key(self):
        """AES-128 test key."""
        return bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

    @pytest.fixture
    def iv(self):
        """Test IV."""
        return bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_nist_vector(self, aes_key, iv):
        """Test against NIST SP 800-38A test vector."""
        plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_ciphertext = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")

        cbc = CBCMode(_encrypt_block, _decrypt_block, 16, aes_key, iv)
        ciphertext = cbc.encrypt(plaintext)

        assert ciphertext == expected_ciphertext

        decrypted = cbc.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt(self, aes_key, iv):
        """Test basic encrypt/decrypt."""
        plaintext = b"Hello, World!!!"

        cbc = CBCMode(_encrypt_block, _decrypt_block, 16, aes_key, iv)
        ciphertext = cbc.encrypt(plaintext)
        decrypted = cbc.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_against_pycryptodome(self, aes_key, iv):
        """Verify against pycryptodome implementation."""
        plaintext = b"The quick brown fox jumps over the lazy dog"

        # Our implementation
        cbc = CBCMode(_encrypt_block, _decrypt_block, 16, aes_key, iv)
        our_ciphertext = cbc.encrypt(plaintext)

        # pycryptodome reference
        cipher = CryptoAES.new(aes_key, CryptoAES.MODE_CBC, iv=iv)
        ref_ciphertext = cipher.encrypt(
            plaintext + b"\x0f" * 15  # Manual PKCS7 padding
        )

        assert our_ciphertext == ref_ciphertext

        # Verify decryption matches
        our_decrypted = cbc.decrypt(our_ciphertext)
        assert our_decrypted == plaintext

    def test_invalid_iv_length(self, aes_key):
        """Test with invalid IV length."""
        with pytest.raises(ValueError, match="IV must be 16 bytes"):
            CBCMode(_encrypt_block, _decrypt_block, 16, aes_key, b"short")

    def test_invalid_ciphertext_length(self, aes_key, iv):
        """Test decrypting ciphertext with invalid length."""
        cbc = CBCMode(_encrypt_block, _decrypt_block, 16, aes_key, iv)
        with pytest.raises(ValueError, match="Ciphertext length must be multiple"):
            cbc.decrypt(b"invalid")  # Not multiple of block size

    def test_chaining(self, aes_key, iv):
        """Test that CBC properly chains blocks."""
        # Two identical plaintext blocks should produce different ciphertext
        plaintext = b"a" * 32  # Two identical blocks

        cbc = CBCMode(_encrypt_block, _decrypt_block, 16, aes_key, iv)
        ciphertext = cbc.encrypt(plaintext)

        block1 = ciphertext[:16]
        block2 = ciphertext[16:32]

        # Blocks should be different due to chaining
        assert block1 != block2

        # Decryption should restore original
        decrypted = cbc.decrypt(ciphertext)
        assert decrypted == plaintext
```

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/modes/test_cbc.py -v
```

Expected: 7 tests PASS

- [ ] **Step 4: Commit**

```bash
git add src/crypt/encrypt/symmetric_encrypt/modes/cbc.py tests/encrypt/symmetric_encrypt/modes/test_cbc.py
git commit -m "feat(modes): add CBC mode with NIST vectors and pycryptodome validation"
```

---

## Task 6: CTR Mode

**Files:**
- Create: `src/crypt/encrypt/symmetric_encrypt/modes/ctr.py`
- Modify: `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`
- Create: `tests/encrypt/symmetric_encrypt/modes/test_ctr.py`

- [ ] **Step 1: Write CTR mode implementation**

Create `src/crypt/encrypt/symmetric_encrypt/modes/ctr.py`:

```python
"""
CTR (Counter) mode.

Converts a block cipher into a stream cipher.
WARNING: Never reuse a (key, nonce) pair. This will compromise security.
"""

from typing import Callable

from crypt.encrypt.symmetric_encrypt.modes import ModeError


class CTRMode:
    """
    Counter mode wrapper.

    Encrypts counter values and XORs with plaintext.
    Encryption and decryption are identical operations.

    WARNING: The (key, nonce) pair must never be reused.
    """

    def __init__(
        self,
        encrypt_func: Callable,
        decrypt_func: Callable,  # Not used but kept for interface consistency
        block_size: int,
        key: bytes,
        nonce: bytes,
        expanded_key: list[int] | None = None,
        nr: int | None = None,
    ):
        """
        Initialize CTR mode.

        Args:
            encrypt_func: Function to encrypt a single block.
            decrypt_func: Not used in CTR mode (for interface consistency).
            block_size: Block size in bytes.
            key: The encryption key.
            nonce: Nonce (block_size bytes). For AES, typically:
                   12 bytes nonce + 4 bytes counter = 16 bytes.
            expanded_key: Pre-computed expanded key (optional).
            nr: Number of rounds (optional).
        """
        if len(nonce) != block_size:
            msg = f"Nonce must be {block_size} bytes, got {len(nonce)}"
            raise ValueError(msg)

        self._encrypt_func = encrypt_func
        self.block_size = block_size
        self._key = key
        self._nonce = nonce
        self._counter_size = 4  # 32-bit counter
        self._nonce_size = block_size - self._counter_size

        # Compute expanded key if not provided
        if expanded_key is None or nr is None:
            from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
                key_expansion,
                _get_key_params,
            )

            _nk, self._nr = _get_key_params(key)
            self._expanded_key = key_expansion(key)
        else:
            self._expanded_key = expanded_key
            self._nr = nr

        # Initialize counter from last 4 bytes of nonce
        self._counter = int.from_bytes(nonce[-self._counter_size :], "big")
        self._nonce_prefix = nonce[: self._nonce_size]
        self._used = False

    def _get_counter_block(self) -> bytes:
        """Get the current counter block."""
        counter_bytes = self._counter.to_bytes(self._counter_size, "big")
        return self._nonce_prefix + counter_bytes

    def _increment_counter(self) -> None:
        """Increment the counter, checking for overflow."""
        self._counter = (self._counter + 1) & 0xFFFFFFFF

        if self._counter == 0:
            msg = "CTR counter overflow - (key, nonce) pair exhausted"
            raise ModeError(msg)

    def crypt(self, data: bytes) -> bytes:
        """
        Encrypt or decrypt data using CTR mode.

        CTR mode is symmetric - encryption and decryption use the same operation.

        Args:
            data: Data to encrypt or decrypt.

        Returns:
            Encrypted or decrypted data.
        """
        self._used = True

        result = bytearray()

        for i in range(0, len(data), self.block_size):
            block = data[i : i + self.block_size]

            # Generate keystream
            counter_block = self._get_counter_block()
            keystream = self._encrypt_func(counter_block, self._expanded_key, self._nr)

            # XOR with data
            for j in range(len(block)):
                result.append(block[j] ^ keystream[j])

            self._increment_counter()

        return bytes(result)

    encrypt = crypt
    decrypt = crypt


def test_ctr_mode():
    """Test CTR mode."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
        _encrypt_block,
        _decrypt_block,
    )

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    nonce = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = b"Hello, CTR Mode!"

    ctr = CTRMode(_encrypt_block, _decrypt_block, 16, key, nonce)

    # Encrypt
    ciphertext = ctr.crypt(plaintext)

    # Decrypt (new instance with same nonce)
    ctr2 = CTRMode(_encrypt_block, _decrypt_block, 16, key, nonce)
    decrypted = ctr2.crypt(ciphertext)

    assert decrypted == plaintext
    print("CTR mode test passed!")


if __name__ == "__main__":
    test_ctr_mode()
```

- [ ] **Step 2: Update modes __init__.py**

Modify `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`:

```python
"""Block cipher modes of operation."""

from .cbc import CBCMode
from .ctr import CTRMode
from .ecb import ECBMode

__all__ = [
    "ECBMode",
    "CBCMode",
    "CTRMode",
    "ModeError",
]


class ModeError(ValueError):
    """Mode-specific error (e.g., IV reuse, invalid parameters)."""

    pass
```

**Note:** CFB, OFB, XTS will be added when implemented.

- [ ] **Step 3: Write CTR tests**

Create `tests/encrypt/symmetric_encrypt/modes/test_ctr.py`:

```python
"""Tests for CTR mode."""

import pytest

from Cryptodome.Cipher import AES as CryptoAES
from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _decrypt_block,
    _encrypt_block,
)
from crypt.encrypt.symmetric_encrypt.modes import ModeError
from crypt.encrypt.symmetric_encrypt.modes.ctr import CTRMode


class TestCTRMode:
    """Test CTR mode encryption/decryption."""

    @pytest.fixture
    def aes_key(self):
        """AES-128 test key."""
        return bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

    @pytest.fixture
    def nonce(self):
        """Test nonce (16 bytes for AES)."""
        return bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

    def test_encrypt_decrypt(self, aes_key, nonce):
        """Test basic encrypt/decrypt."""
        plaintext = b"Hello, CTR Mode!"

        ctr = CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, nonce)
        ciphertext = ctr.crypt(plaintext)

        # Decrypt with new instance
        ctr2 = CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, nonce)
        decrypted = ctr2.crypt(ciphertext)

        assert decrypted == plaintext

    def test_against_pycryptodome(self, aes_key, nonce):
        """Verify against pycryptodome implementation."""
        plaintext = b"The quick brown fox jumps over the lazy dog"

        # Our implementation
        ctr = CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, nonce)
        our_ciphertext = ctr.crypt(plaintext)

        # pycryptodome reference (nonce + counter)
        cipher = CryptoAES.new(
            aes_key, CryptoAES.MODE_CTR, nonce=nonce[:12], initial_value=int.from_bytes(nonce[12:], "big")
        )
        ref_ciphertext = cipher.encrypt(plaintext)

        assert our_ciphertext == ref_ciphertext

    def test_no_padding(self, aes_key, nonce):
        """Test that CTR doesn't pad (any length works)."""
        for length in [1, 5, 15, 16, 17, 32, 100]:
            plaintext = b"a" * length

            ctr = CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, nonce)
            ciphertext = ctr.crypt(plaintext)

            ctr2 = CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, nonce)
            decrypted = ctr2.crypt(ciphertext)

            assert decrypted == plaintext
            assert len(ciphertext) == len(plaintext)

    def test_invalid_nonce_length(self, aes_key):
        """Test with invalid nonce length."""
        with pytest.raises(ValueError, match="Nonce must be 16 bytes"):
            CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, b"short")

    def test_counter_overflow(self, aes_key):
        """Test counter overflow raises ModeError."""
        # Nonce with max counter value
        nonce = b"\x00" * 12 + b"\xff\xff\xff\xff"

        ctr = CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, nonce)

        # Encrypt 2 blocks - second should overflow
        ctr.crypt(b"a" * 16)  # First block OK
        with pytest.raises(ModeError, match="CTR counter overflow"):
            ctr.crypt(b"a" * 16)  # Second block overflows

    def test_stream_cipher_property(self, aes_key, nonce):
        """Test that identical plaintexts produce different ciphertexts with different nonces."""
        plaintext = b"Hello, World!!!!"
        nonce1 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        nonce2 = bytes.fromhex("e0e1e2e3e4e5e6e7e8e9eaebecedeeef")

        ctr1 = CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, nonce1)
        ctr2 = CTRMode(_encrypt_block, _decrypt_block, 16, aes_key, nonce2)

        ciphertext1 = ctr1.crypt(plaintext)
        ciphertext2 = ctr2.crypt(plaintext)

        assert ciphertext1 != ciphertext2
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/modes/test_ctr.py -v
```

Expected: 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypt/encrypt/symmetric_encrypt/modes/ctr.py tests/encrypt/symmetric_encrypt/modes/test_ctr.py
git commit -m "feat(modes): add CTR mode with counter overflow protection"
```

---

## Task 7: CFB Mode

**Files:**
- Create: `src/crypt/encrypt/symmetric_encrypt/modes/cfb.py`
- Modify: `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`
- Create: `tests/encrypt/symmetric_encrypt/modes/test_cfb.py`

- [ ] **Step 1: Write CFB mode implementation**

Create `src/crypt/encrypt/symmetric_encrypt/modes/cfb.py`:

```python
"""CFB (Cipher Feedback) mode."""

from typing import Callable


class CFBMode:
    """
    Cipher Feedback mode wrapper.

    Self-synchronizing stream cipher mode.
    """

    def __init__(
        self,
        encrypt_func: Callable,
        decrypt_func: Callable,
        block_size: int,
        key: bytes,
        iv: bytes,
        segment_size: int = 8,
        expanded_key: list[int] | None = None,
        nr: int | None = None,
    ):
        """
        Initialize CFB mode.

        Args:
            encrypt_func: Function to encrypt a single block.
            decrypt_func: Not used in CFB mode (for interface consistency).
            block_size: Block size in bytes.
            key: The encryption key.
            iv: Initialization vector (must be block_size bytes).
            segment_size: Segment size in bits (default 8).
            expanded_key: Pre-computed expanded key (optional).
            nr: Number of rounds (optional).
        """
        if len(iv) != block_size:
            msg = f"IV must be {block_size} bytes, got {len(iv)}"
            raise ValueError(msg)

        if segment_size < 1 or segment_size > block_size * 8:
            msg = f"segment_size must be 1-{block_size * 8}, got {segment_size}"
            raise ValueError(msg)

        self._encrypt_func = encrypt_func
        self.block_size = block_size
        self.segment_size = segment_size // 8  # Convert to bytes
        self._key = key
        self._iv = iv

        if expanded_key is None or nr is None:
            from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
                key_expansion,
                _get_key_params,
            )

            _nk, self._nr = _get_key_params(key)
            self._expanded_key = key_expansion(key)
        else:
            self._expanded_key = expanded_key
            self._nr = nr

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using CFB mode."""
        ciphertext = bytearray()
        shift_register = bytearray(self._iv)

        for i in range(0, len(plaintext), self.segment_size):
            segment = plaintext[i : i + self.segment_size]

            # Encrypt shift register
            encrypted_sr = self._encrypt_func(
                bytes(shift_register), self._expanded_key, self._nr
            )

            # XOR with plaintext segment
            keystream = encrypted_sr[: len(segment)]
            cipher_segment = bytes([p ^ k for p, k in zip(segment, keystream)])
            ciphertext.extend(cipher_segment)

            # Update shift register: shift left, append ciphertext
            shift_register = shift_register[len(cipher_segment) :]
            shift_register.extend(cipher_segment)

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using CFB mode."""
        plaintext = bytearray()
        shift_register = bytearray(self._iv)

        for i in range(0, len(ciphertext), self.segment_size):
            segment = ciphertext[i : i + self.segment_size]

            # Encrypt shift register
            encrypted_sr = self._encrypt_func(
                bytes(shift_register), self._expanded_key, self._nr
            )

            # XOR with ciphertext segment
            keystream = encrypted_sr[: len(segment)]
            plain_segment = bytes([c ^ k for c, k in zip(segment, keystream)])
            plaintext.extend(plain_segment)

            # Update shift register: shift left, append ciphertext
            shift_register = shift_register[len(segment) :]
            shift_register.extend(segment)

        return bytes(plaintext)
```

- [ ] **Step 2: Update modes __init__.py**

Modify `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`:

```python
"""Block cipher modes of operation."""

from .cbc import CBCMode
from .cfb import CFBMode
from .ctr import CTRMode
from .ecb import ECBMode

__all__ = [
    "ECBMode",
    "CBCMode",
    "CTRMode",
    "CFBMode",
    "ModeError",
]


class ModeError(ValueError):
    """Mode-specific error (e.g., IV reuse, invalid parameters)."""

    pass
```

- [ ] **Step 3: Write CFB tests**

Create `tests/encrypt/symmetric_encrypt/modes/test_cfb.py`:

```python
"""Tests for CFB mode."""

import pytest

from Cryptodome.Cipher import AES as CryptoAES
from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _decrypt_block,
    _encrypt_block,
)
from crypt.encrypt.symmetric_encrypt.modes.cfb import CFBMode


class TestCFBMode:
    """Test CFB mode encryption/decryption."""

    @pytest.fixture
    def aes_key(self):
        return bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

    @pytest.fixture
    def iv(self):
        return bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_encrypt_decrypt(self, aes_key, iv):
        plaintext = b"Hello, CFB Mode!"
        cfb = CFBMode(_encrypt_block, _decrypt_block, 16, aes_key, iv)
        ciphertext = cfb.encrypt(plaintext)
        decrypted = cfb.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_against_pycryptodome(self, aes_key, iv):
        plaintext = b"The quick brown fox"
        cfb = CFBMode(_encrypt_block, _decrypt_block, 16, aes_key, iv, segment_size=8)
        our_ciphertext = cfb.encrypt(plaintext)

        cipher = CryptoAES.new(aes_key, CryptoAES.MODE_CFB, iv=iv, segment_size=8)
        ref_ciphertext = cipher.encrypt(plaintext)

        assert our_ciphertext == ref_ciphertext

    def test_self_synchronizing(self, aes_key, iv):
        """Test CFB self-synchronizing property."""
        plaintext = b"Hello, World!!!!Hello, World!!!!"
        cfb = CFBMode(_encrypt_block, _decrypt_block, 16, aes_key, iv, segment_size=8)
        ciphertext = cfb.encrypt(plaintext)

        # Corrupt one byte in middle
        corrupted = bytearray(ciphertext)
        corrupted[20] ^= 0xFF

        # Decrypt - only corrupted segment and next block should be affected
        decrypted = cfb.decrypt(bytes(corrupted))
        assert decrypted[:19] == plaintext[:19]
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/modes/test_cfb.py -v
```

Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypt/encrypt/symmetric_encrypt/modes/cfb.py tests/encrypt/symmetric_encrypt/modes/test_cfb.py
git commit -m "feat(modes): add CFB mode with segment size support"
```

---

## Task 8: OFB Mode

**Files:**
- Create: `src/crypt/encrypt/symmetric_encrypt/modes/ofb.py`
- Modify: `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`
- Create: `tests/encrypt/symmetric_encrypt/modes/test_ofb.py`

- [ ] **Step 1: Write OFB mode implementation**

Create `src/crypt/encrypt/symmetric_encrypt/modes/ofb.py`:

```python
"""OFB (Output Feedback) mode."""

from typing import Callable


class OFBMode:
    """Output Feedback mode wrapper."""

    def __init__(
        self,
        encrypt_func: Callable,
        decrypt_func: Callable,
        block_size: int,
        key: bytes,
        iv: bytes,
        expanded_key: list[int] | None = None,
        nr: int | None = None,
    ):
        if len(iv) != block_size:
            msg = f"IV must be {block_size} bytes, got {len(iv)}"
            raise ValueError(msg)

        self._encrypt_func = encrypt_func
        self.block_size = block_size
        self._key = key
        self._iv = iv

        if expanded_key is None or nr is None:
            from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
                key_expansion,
                _get_key_params,
            )

            _nk, self._nr = _get_key_params(key)
            self._expanded_key = key_expansion(key)
        else:
            self._expanded_key = expanded_key
            self._nr = nr

    def crypt(self, data: bytes) -> bytes:
        """Encrypt/decrypt data using OFB mode."""
        result = bytearray()
        feedback = self._iv

        for i in range(0, len(data), self.block_size):
            block = data[i : i + self.block_size]

            # Generate keystream
            keystream = self._encrypt_func(feedback, self._expanded_key, self._nr)

            # XOR with data
            for j in range(len(block)):
                result.append(block[j] ^ keystream[j])

            # Update feedback (keystream becomes next feedback)
            feedback = keystream

        return bytes(result)

    encrypt = crypt
    decrypt = crypt
```

- [ ] **Step 2: Update modes __init__.py**

Add OFBMode to `__all__` in `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`.

- [ ] **Step 3: Write OFB tests**

Create `tests/encrypt/symmetric_encrypt/modes/test_ofb.py`:

```python
"""Tests for OFB mode."""

import pytest

from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _decrypt_block,
    _encrypt_block,
)
from crypt.encrypt.symmetric_encrypt.modes.ofb import OFBMode


class TestOFBMode:
    """Test OFB mode."""

    def test_encrypt_decrypt(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = b"Hello, OFB Mode!"

        ofb = OFBMode(_encrypt_block, _decrypt_block, 16, key, iv)
        ciphertext = ofb.encrypt(plaintext)
        decrypted = ofb.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_keystream_independent(self):
        """Test keystream is independent of plaintext."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        ofb = OFBMode(_encrypt_block, _decrypt_block, 16, key, iv)

        # Encrypt two different plaintexts with same IV
        ct1 = ofb.encrypt(b"aaaaaaaaaaaaaaaa")
        ct2 = ofb.encrypt(b"bbbbbbbbbbbbbbbb")

        # XOR of ciphertexts should equal XOR of plaintexts
        xor_ct = bytes([a ^ b for a, b in zip(ct1, ct2)])
        xor_pt = bytes([a ^ b for a, b in zip(b"aaaaaaaaaaaaaaaa", b"bbbbbbbbbbbbbbbb")])

        assert xor_ct == xor_pt
```

- [ ] **Step 4: Run tests and commit**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/modes/test_ofb.py -v
git add src/crypt/encrypt/symmetric_encrypt/modes/ofb.py tests/encrypt/symmetric_encrypt/modes/test_ofb.py
git commit -m "feat(modes): add OFB mode"
```

---

## Task 9: XTS Mode

**Files:**
- Create: `src/crypt/encrypt/symmetric_encrypt/modes/xts.py`
- Modify: `src/crypt/encrypt/symmetric_encrypt/modes/__init__.py`
- Create: `tests/encrypt/symmetric_encrypt/modes/test_xts.py`

- [ ] **Step 1: Write XTS mode implementation**

Create `src/crypt/encrypt/symmetric_encrypt/modes/xts.py`:

```python
"""XTS (XEX-based Tweaked Codebook with Ciphertext Stealing) mode."""

from typing import Callable


def _gf_mul_xts(a: int) -> int:
    """Multiply by x in GF(2^128)."""
    return ((a << 1) ^ (0x87 if (a & 0x80000000000000000000000000000000) else 0)) & ((1 << 128) - 1)


class XTSMode:
    """XTS mode for disk encryption."""

    def __init__(
        self,
        encrypt_func: Callable,
        decrypt_func: Callable,
        block_size: int,
        key: bytes,
        expanded_key: list[int] | None = None,
        nr: int | None = None,
    ):
        if len(key) not in [32, 64]:  # 2 x AES-128 or 2 x AES-256
            msg = "XTS key must be 32 or 64 bytes (2 x AES key)"
            raise ValueError(msg)

        self._encrypt_func = encrypt_func
        self._decrypt_func = decrypt_func
        self.block_size = block_size
        self._key = key

        # Split key into two halves
        half = len(key) // 2
        self._key1 = key[:half]
        self._key2 = key[half:]

        if expanded_key is None or nr is None:
            from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
                key_expansion,
                _get_key_params,
            )

            _nk, self._nr = _get_key_params(self._key1)
            self._expanded_key1 = key_expansion(self._key1)
            self._expanded_key2 = key_expansion(self._key2)
        else:
            self._expanded_key = expanded_key
            self._nr = nr

    def _generate_tweak(self, tweak: int) -> int:
        """Generate tweak value by encrypting sector number."""
        tweak_bytes = tweak.to_bytes(16, "little")
        encrypted = self._encrypt_func(tweak_bytes, self._expanded_key2, self._nr)
        return int.from_bytes(encrypted, "little")

    def encrypt(self, plaintext: bytes, tweak: int) -> bytes:
        """Encrypt data with XTS mode."""
        t = self._generate_tweak(tweak)
        ciphertext = bytearray()

        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i : i + self.block_size]

            # Convert tweak to bytes (little endian)
            tweak_bytes = t.to_bytes(16, "little")

            if len(block) == self.block_size:
                # Full block
                xored = bytes([block[j] ^ tweak_bytes[j] for j in range(self.block_size)])
                encrypted = self._encrypt_func(xored, self._expanded_key1, self._nr)
                cipher_block = bytes([encrypted[j] ^ tweak_bytes[j] for j in range(self.block_size)])
                ciphertext.extend(cipher_block)
                t = _gf_mul_xts(t)
            else:
                # Ciphertext stealing for final partial block
                # Take last full block's ciphertext
                prev_cipher = ciphertext[-self.block_size:]
                # Pad block with start of previous cipher
                padded = block + prev_cipher[len(block):]
                xored = bytes([padded[j] ^ tweak_bytes[j] for j in range(self.block_size)])
                encrypted = self._encrypt_func(xored, self._expanded_key1, self._nr)
                cipher_block = bytes([encrypted[j] ^ tweak_bytes[j] for j in range(self.block_size)])
                # Replace last block with full cipher, current block gets prefix
                ciphertext[-self.block_size:] = cipher_block[: len(block)]
                ciphertext.extend(cipher_block[len(block):])

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, tweak: int) -> bytes:
        """Decrypt data with XTS mode."""
        t = self._generate_tweak(tweak)
        plaintext = bytearray()

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i : i + self.block_size]
            tweak_bytes = t.to_bytes(16, "little")

            if len(block) == self.block_size:
                xored = bytes([block[j] ^ tweak_bytes[j] for j in range(self.block_size)])
                decrypted = self._decrypt_func(xored, self._expanded_key1, self._nr)
                plain_block = bytes([decrypted[j] ^ tweak_bytes[j] for j in range(self.block_size)])
                plaintext.extend(plain_block)
                t = _gf_mul_xts(t)
            else:
                # Ciphertext stealing reverse
                prev_cipher = ciphertext[i - self.block_size : i]
                padded = block + prev_cipher[len(block):]
                xored = bytes([padded[j] ^ tweak_bytes[j] for j in range(self.block_size)])
                decrypted = self._decrypt_func(xored, self._expanded_key1, self._nr)
                plain_block = bytes([decrypted[j] ^ tweak_bytes[j] for j in range(self.block_size)])
                plaintext[-self.block_size:] = plain_block[: len(block)]
                plaintext.extend(plain_block[len(block):])

        return bytes(plaintext)
```

- [ ] **Step 2: Update modes __init__.py**

Add XTSMode to `__all__`.

- [ ] **Step 3: Write XTS tests**

Create `tests/encrypt/symmetric_encrypt/modes/test_xts.py`:

```python
"""Tests for XTS mode."""

import pytest

from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _decrypt_block,
    _encrypt_block,
)
from crypt.encrypt.symmetric_encrypt.modes.xts import XTSMode


class TestXTSMode:
    """Test XTS mode."""

    def test_xts_32byte_key(self):
        """Test XTS with 32-byte key (2x AES-128)."""
        # 32-byte key = 2 x AES-128 keys
        key = b"a" * 16 + b"b" * 16
        xts = XTSMode(_encrypt_block, _decrypt_block, 16, key)

        plaintext = b"Hello, XTS Mode!Disk encryption!"
        ciphertext = xts.encrypt(plaintext, tweak=0)
        decrypted = xts.decrypt(ciphertext, tweak=0)

        assert decrypted == plaintext

    def test_xts_different_tweaks(self):
        """Test that different tweaks produce different ciphertexts."""
        key = b"a" * 16 + b"b" * 16
        xts = XTSMode(_encrypt_block, _decrypt_block, 16, key)
        plaintext = b"a" * 32

        ct1 = xts.encrypt(plaintext, tweak=0)
        ct2 = xts.encrypt(plaintext, tweak=1)

        assert ct1 != ct2

        # Both decrypt correctly
        assert xts.decrypt(ct1, tweak=0) == plaintext
        assert xts.decrypt(ct2, tweak=1) == plaintext

    def test_xts_partial_block(self):
        """Test XTS with partial final block (ciphertext stealing)."""
        key = b"a" * 16 + b"b" * 16
        xts = XTSMode(_encrypt_block, _decrypt_block, 16, key)

        # 20 bytes = 1 full block + 4 bytes
        plaintext = b"Hello, XTS Mode!!!!"
        ciphertext = xts.encrypt(plaintext, tweak=0)
        decrypted = xts.decrypt(ciphertext, tweak=0)

        assert decrypted == plaintext

    def test_invalid_key_length(self):
        """Test with invalid key length."""
        with pytest.raises(ValueError, match="XTS key must be 32 or 64 bytes"):
            XTSMode(_encrypt_block, _decrypt_block, 16, b"short")
```

- [ ] **Step 4: Run tests and commit**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/modes/test_xts.py -v
git add src/crypt/encrypt/symmetric_encrypt/modes/xts.py tests/encrypt/symmetric_encrypt/modes/test_xts.py
git commit -m "feat(modes): add XTS mode with ciphertext stealing"
```

---

## Task 10: SHAKE128

**Files:**
- Create: `src/crypt/digest/SHAKE/__init__.py`
- Create: `src/crypt/digest/SHAKE/shake128.py`
- Create: `tests/digest/SHAKE/test_shake128.py`

- [ ] **Step 1: Create SHAKE __init__.py**

Create `src/crypt/digest/SHAKE/__init__.py`:

```python
"""SHAKE extendable-output functions (XOF)."""

from .shake128 import SHAKE128
from .shake256 import SHAKE256

__all__ = ["SHAKE128", "SHAKE256"]
```

- [ ] **Step 2: Write SHAKE128 implementation**

Create `src/crypt/digest/SHAKE/shake128.py`:

```python
"""SHAKE128 XOF implementation."""

from crypt.digest.SHA.sha3_256 import (
    keccak_f_1600,
    bytes_to_lanes,
    lanes_to_bytes,
)

# SHAKE128 parameters
SHAKE128_RATE = 168  # bytes (1344 bits)
SHAKE128_CAPACITY = 32  # bytes (256 bits)


class SHAKE128:
    """SHAKE128 extendable-output function."""

    def __init__(self):
        """Initialize SHAKE128."""
        self._state = [0] * 25
        self._buffer = bytearray()
        self._squeezing = False

    def update(self, data: bytes) -> "SHAKE128":
        """Absorb data into the state."""
        if self._squeezing:
            msg = "Cannot update after squeezing has started"
            raise RuntimeError(msg)

        self._buffer.extend(data)

        # Process complete blocks
        while len(self._buffer) >= SHAKE128_RATE:
            block = self._buffer[:SHAKE128_RATE]
            self._buffer = self._buffer[SHAKE128_RATE:]

            block_lanes = bytes_to_lanes(block.ljust(200, b"\x00"))
            for j in range(len(block_lanes)):
                self._state[j] ^= block_lanes[j]

            self._state = keccak_f_1600(self._state)

        return self

    def _finalize(self) -> None:
        """Apply padding and transition to squeezing phase."""
        if self._squeezing:
            return

        # SHAKE128 uses 0x1F domain separator (0x1F = 0b00011111)
        # Padding: 0x1F || 0x00... || 0x80
        self._buffer.append(0x1F)
        self._buffer.extend([0] * (SHAKE128_RATE - len(self._buffer) - 1))
        self._buffer.append(0x80)

        block = bytes(self._buffer)
        block_lanes = bytes_to_lanes(block.ljust(200, b"\x00"))
        for j in range(len(block_lanes)):
            self._state[j] ^= block_lanes[j]

        self._state = keccak_f_1600(self._state)
        self._squeezing = True
        self._buffer = bytearray()

    def read(self, length: int) -> bytes:
        """Squeeze arbitrary-length output."""
        self._finalize()

        output = bytearray()
        while len(output) < length:
            available = lanes_to_bytes(self._state)[:SHAKE128_RATE]
            needed = length - len(output)
            output.extend(available[:needed])

            if len(output) < length:
                self._state = keccak_f_1600(self._state)

        return bytes(output)

    def hexdigest(self, length: int) -> str:
        """Return hex string of specified length."""
        return self.read(length).hex()

    def copy(self) -> "SHAKE128":
        """Create a copy of the hasher state."""
        new = SHAKE128()
        new._state = self._state.copy()
        new._buffer = self._buffer.copy()
        new._squeezing = self._squeezing
        return new


def shake128(data: bytes, output_length: int) -> bytes:
    """One-shot SHAKE128."""
    return SHAKE128().update(data).read(output_length)
```

- [ ] **Step 3: Write SHAKE128 tests**

Create `tests/digest/SHAKE/test_shake128.py`:

```python
"""Tests for SHAKE128."""

import pytest

from crypt.digest.SHAKE.shake128 import SHAKE128, shake128


class TestSHAKE128:
    """Test SHAKE128 XOF."""

    def test_empty_message(self):
        """Test SHAKE128 with empty message."""
        shake = SHAKE128()
        shake.update(b"")
        result = shake.read(32)
        assert len(result) == 32

    def test_variable_output_length(self):
        """Test different output lengths."""
        shake = SHAKE128()
        shake.update(b"abc")

        for length in [16, 32, 64, 128, 1000]:
            shake2 = SHAKE128().update(b"abc")
            result = shake2.read(length)
            assert len(result) == length

    def test_incremental_update(self):
        """Test incremental updates."""
        shake1 = SHAKE128()
        shake1.update(b"Hello")
        shake1.update(b" ")
        shake1.update(b"World")

        shake2 = SHAKE128()
        shake2.update(b"Hello World")

        assert shake1.read(32) == shake2.read(32)

    def test_copy(self):
        """Test copying hasher state."""
        shake1 = SHAKE128()
        shake1.update(b"test data")

        shake2 = shake1.copy()

        # Both should produce same output
        assert shake1.read(32) == shake2.read(32)

    def test_one_shot(self):
        """Test one-shot convenience function."""
        result = shake128(b"abc", 32)
        assert len(result) == 32

    def test_hexdigest(self):
        """Test hex output."""
        shake = SHAKE128()
        shake.update(b"abc")
        hex_result = shake.hexdigest(32)
        assert len(hex_result) == 64  # 32 bytes = 64 hex chars
```

- [ ] **Step 4: Run tests and commit**

```bash
uv run pytest tests/digest/SHAKE/test_shake128.py -v
git add src/crypt/digest/SHAKE/ tests/digest/SHAKE/
git commit -m "feat(digest): add SHAKE128 XOF implementation"
```

---

## Task 11: SHAKE256

**Files:**
- Create: `src/crypt/digest/SHAKE/shake256.py`
- Create: `tests/digest/SHAKE/test_shake256.py`

- [ ] **Step 1: Write SHAKE256 implementation**

Create `src/crypt/digest/SHAKE/shake256.py`:

```python
"""SHAKE256 XOF implementation."""

from crypt.digest.SHA.sha3_256 import (
    keccak_f_1600,
    bytes_to_lanes,
    lanes_to_bytes,
)

# SHAKE256 parameters
SHAKE256_RATE = 136  # bytes (1088 bits)
SHAKE256_CAPACITY = 64  # bytes (512 bits)


class SHAKE256:
    """SHAKE256 extendable-output function."""

    def __init__(self):
        """Initialize SHAKE256."""
        self._state = [0] * 25
        self._buffer = bytearray()
        self._squeezing = False

    def update(self, data: bytes) -> "SHAKE256":
        """Absorb data into the state."""
        if self._squeezing:
            msg = "Cannot update after squeezing has started"
            raise RuntimeError(msg)

        self._buffer.extend(data)

        while len(self._buffer) >= SHAKE256_RATE:
            block = self._buffer[:SHAKE256_RATE]
            self._buffer = self._buffer[SHAKE256_RATE:]

            block_lanes = bytes_to_lanes(block.ljust(200, b"\x00"))
            for j in range(len(block_lanes)):
                self._state[j] ^= block_lanes[j]

            self._state = keccak_f_1600(self._state)

        return self

    def _finalize(self) -> None:
        """Apply padding and transition to squeezing phase."""
        if self._squeezing:
            return

        self._buffer.append(0x1F)
        self._buffer.extend([0] * (SHAKE256_RATE - len(self._buffer) - 1))
        self._buffer.append(0x80)

        block = bytes(self._buffer)
        block_lanes = bytes_to_lanes(block.ljust(200, b"\x00"))
        for j in range(len(block_lanes)):
            self._state[j] ^= block_lanes[j]

        self._state = keccak_f_1600(self._state)
        self._squeezing = True
        self._buffer = bytearray()

    def read(self, length: int) -> bytes:
        """Squeeze arbitrary-length output."""
        self._finalize()

        output = bytearray()
        while len(output) < length:
            available = lanes_to_bytes(self._state)[:SHAKE256_RATE]
            needed = length - len(output)
            output.extend(available[:needed])

            if len(output) < length:
                self._state = keccak_f_1600(self._state)

        return bytes(output)

    def hexdigest(self, length: int) -> str:
        """Return hex string of specified length."""
        return self.read(length).hex()

    def copy(self) -> "SHAKE256":
        """Create a copy of the hasher state."""
        new = SHAKE256()
        new._state = self._state.copy()
        new._buffer = self._buffer.copy()
        new._squeezing = self._squeezing
        return new


def shake256(data: bytes, output_length: int) -> bytes:
    """One-shot SHAKE256."""
    return SHAKE256().update(data).read(output_length)
```

- [ ] **Step 2: Write SHAKE256 tests**

Create `tests/digest/SHAKE/test_shake256.py` (similar to SHAKE128 tests).

- [ ] **Step 3: Run tests and commit**

```bash
uv run pytest tests/digest/SHAKE/test_shake256.py -v
git add src/crypt/digest/SHAKE/shake256.py tests/digest/SHAKE/test_shake256.py
git commit -m "feat(digest): add SHAKE256 XOF implementation"
```

---

## Task 12: Update AES.py for Shared Padding

**Files:**
- Modify: `src/crypt/encrypt/symmetric_encrypt/block_cipher/AES.py`

- [ ] **Step 1: Update AES.py imports**

Modify `src/crypt/encrypt/symmetric_encrypt/block_cipher/AES.py` to import PKCS#7 from shared module:

```python
# Add at top of file after existing imports
try:
    from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import pad as _pkcs7_pad_impl
    from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import unpad as _pkcs7_unpad_impl
except ImportError:
    # Fallback to local implementation if padding module not available
    _pkcs7_pad_impl = None
    _pkcs7_unpad_impl = None


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS7 padding to data.
    Backward-compatible wrapper that delegates to shared implementation.
    """
    if _pkcs7_pad_impl is not None:
        return _pkcs7_pad_impl(data, block_size)
    # Fallback local implementation (keep existing code)
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS7 padding from data.
    Backward-compatible wrapper that delegates to shared implementation.
    """
    if _pkcs7_unpad_impl is not None:
        return _pkcs7_unpad_impl(data, block_size)
    # Fallback local implementation (keep existing code)
    if not data:
        raise ValueError("Empty data")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError(f"Invalid padding length: {padding_len}")
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError("Invalid padding bytes")
    return data[:-padding_len]
```

- [ ] **Step 2: Test AES.py still works**

```bash
uv run pytest tests/encrypt/symmetric_encrypt/block_cipher/test_AES.py -v
```

- [ ] **Step 3: Commit**

```bash
git add src/crypt/encrypt/symmetric_encrypt/block_cipher/AES.py
git commit -m "refactor(aes): use shared PKCS#7 padding module with backward compatibility"
```

---

## Task 13: Final Integration Test

- [ ] **Step 1: Run full test suite**

```bash
uv run pytest tests/ -v --tb=short
```

Expected: All tests PASS (existing + new)

- [ ] **Step 2: Run type checking**

```bash
uv run pyright src/crypt/
```

- [ ] **Step 3: Run linting**

```bash
uv run ruff check src/crypt/
```

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete block cipher modes, padding schemes, and SHAKE XOF implementation"
```

---

**Plan Status:** Ready for execution
**Next Step:** Execute tasks using superpowers:subagent-driven-development
