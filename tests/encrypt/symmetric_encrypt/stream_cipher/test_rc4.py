# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_rc4.py
# @time    : 2026/3/17
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for RC4 stream cipher

"""
Test suite for RC4 stream cipher implementation.

RC4 is a symmetric stream cipher that encrypts and decrypts using the same operation.
Tests include:
- Known test vectors
- Round-trip encryption/decryption
- Comparison with pycryptodome reference implementation
- Various key lengths
"""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.stream_cipher.rc4 import rc4_encrypt_decrypt

import pytest
from Crypto.Cipher import ARC4


class TestRC4:
    """Test cases for RC4 stream cipher."""

    def test_rc4_basic_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        key = b"secretkey"
        plaintext = b"Hello, World!"

        # Encrypt
        ciphertext = rc4_encrypt_decrypt(plaintext, key)
        # Decrypt (same operation for RC4)
        decrypted = rc4_encrypt_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_rc4_against_pycryptodome(self):
        """Test RC4 output matches pycryptodome reference."""
        key = b"testkey123"
        plaintext = b"Hello, RC4!"

        # Our implementation
        our_ciphertext = rc4_encrypt_decrypt(plaintext, key)

        # Reference implementation
        ref_cipher = ARC4.new(key)
        ref_ciphertext = ref_cipher.encrypt(plaintext)

        assert our_ciphertext == ref_ciphertext

    @pytest.mark.parametrize(
        ("key", "plaintext"),
        [
            (b"k", b"a"),  # Minimum length
            (b"short", b"test"),
            (b"exactly16bytes!!", b"exactly16bytes!!"),
            (b"this is a longer key for testing purposes", b"test data"),
            (b"\x00\x01\x02\x03\x04\x05", b"\xff\xfe\xfd\xfc"),  # Binary data
        ],
    )
    def test_rc4_various_key_lengths(self, key, plaintext):
        """Test RC4 with various key and plaintext lengths."""
        ciphertext = rc4_encrypt_decrypt(plaintext, key)
        decrypted = rc4_encrypt_decrypt(ciphertext, key)

        assert decrypted == plaintext

        # Verify against reference
        ref_cipher = ARC4.new(key)
        ref_ciphertext = ref_cipher.encrypt(plaintext)
        assert ciphertext == ref_ciphertext

    def test_rc4_empty_plaintext(self):
        """Test RC4 with empty plaintext."""
        key = b"secretkey"
        plaintext = b""

        ciphertext = rc4_encrypt_decrypt(plaintext, key)
        decrypted = rc4_encrypt_decrypt(ciphertext, key)

        assert decrypted == plaintext
        assert ciphertext == b""

    def test_rc4_large_data(self):
        """Test RC4 with large data."""
        key = b"secretkey"
        plaintext = b"A" * 10000

        ciphertext = rc4_encrypt_decrypt(plaintext, key)
        decrypted = rc4_encrypt_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_rc4_binary_data(self):
        """Test RC4 with binary data (all byte values)."""
        key = bytes(range(32))  # Key with all byte values 0-31
        plaintext = bytes(range(256))  # All possible byte values

        ciphertext = rc4_encrypt_decrypt(plaintext, key)
        decrypted = rc4_encrypt_decrypt(ciphertext, key)

        assert decrypted == plaintext

        # Verify against reference
        ref_cipher = ARC4.new(key)
        ref_ciphertext = ref_cipher.encrypt(plaintext)
        assert ciphertext == ref_ciphertext

    def test_rc4_unicode_key(self):
        """Test RC4 with UTF-8 encoded key."""
        key = "密钥".encode()  # Chinese characters
        plaintext = b"Hello, World!"

        ciphertext = rc4_encrypt_decrypt(plaintext, key)
        decrypted = rc4_encrypt_decrypt(ciphertext, key)

        assert decrypted == plaintext

        # Verify against reference
        ref_cipher = ARC4.new(key)
        ref_ciphertext = ref_cipher.encrypt(plaintext)
        assert ciphertext == ref_ciphertext

    def test_rc4_deterministic(self):
        """Test that RC4 is deterministic (same key + plaintext = same ciphertext)."""
        key = b"secretkey"
        plaintext = b"Hello, World!"

        ciphertext1 = rc4_encrypt_decrypt(plaintext, key)
        ciphertext2 = rc4_encrypt_decrypt(plaintext, key)

        assert ciphertext1 == ciphertext2

    def test_rc4_different_keys(self):
        """Test that different keys produce different ciphertexts."""
        plaintext = b"Hello, World!"
        key1 = b"key1"
        key2 = b"key2"

        ciphertext1 = rc4_encrypt_decrypt(plaintext, key1)
        ciphertext2 = rc4_encrypt_decrypt(plaintext, key2)

        assert ciphertext1 != ciphertext2

    def test_rc4_same_key_different_plaintext(self):
        """Test that same key with different plaintext produces different ciphertexts."""
        key = b"secretkey"
        plaintext1 = b"Hello"
        plaintext2 = b"World"

        ciphertext1 = rc4_encrypt_decrypt(plaintext1, key)
        ciphertext2 = rc4_encrypt_decrypt(plaintext2, key)

        assert ciphertext1 != ciphertext2

    def test_rc4_stateless(self):
        """Test that each encryption is independent (stateless)."""
        key = b"secretkey"
        plaintext1 = b"First message"
        plaintext2 = b"Second message"

        # First encryption
        ciphertext1 = rc4_encrypt_decrypt(plaintext1, key)

        # Second encryption should produce same result as if we encrypted plaintext2 fresh
        ciphertext2 = rc4_encrypt_decrypt(plaintext2, key)
        ref_cipher = ARC4.new(key)
        ref_ciphertext2 = ref_cipher.encrypt(plaintext2)

        assert ciphertext2 == ref_ciphertext2

    def test_rc4_known_vector(self):
        """Test RC4 against known test vector from Wikipedia."""
        # Key: "Key", Plaintext: "Plaintext"
        # Expected ciphertext from RC4 reference
        key = b"Key"
        plaintext = b"Plaintext"
        expected_ciphertext = bytes(
            [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3])

        ciphertext = rc4_encrypt_decrypt(plaintext, key)

        assert ciphertext == expected_ciphertext
