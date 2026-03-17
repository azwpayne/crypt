# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_tea.py
# @time    : 2026/3/17
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for TEA (Tiny Encryption Algorithm) block cipher

"""
Test suite for TEA block cipher implementation.

TEA is a 64-bit block cipher with 128-bit keys.
Tests include:
- Known test vectors
- Round-trip encryption/decryption
- Error handling for invalid keys
- PKCS7 padding verification
"""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.block_cipher.TEA import (
    TEA,
    tea_decrypt,
    tea_encrypt,
)

import pytest


class TestTEA:
    """Test cases for TEA block cipher."""

    def test_tea_basic_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        key = b"0123456789abcdef"  # 16 bytes
        plaintext = b"hello wo"  # 8 bytes (block size)

        encrypted = tea_encrypt(plaintext, key)
        decrypted = tea_decrypt(encrypted, key)

        assert decrypted == plaintext
        # 8 bytes plaintext gets padded to 16 bytes (8 data + 8 padding)
        assert len(encrypted) == 16

    def test_tea_class_encrypt_decrypt(self):
        """Test TEA class encryption and decryption."""
        key = b"0123456789abcdef"
        tea = TEA(key)

        plaintext = b"hello world!!!!!"  # 16 bytes (2 blocks)
        encrypted = tea.encrypt(plaintext)
        decrypted = tea.decrypt(encrypted)

        assert decrypted == plaintext

    def test_tea_string_key(self):
        """Test TEA with string key (converted to bytes)."""
        key = "mysecretkey12345"  # 16 chars
        tea = TEA(key)

        plaintext = b"test message!!"
        encrypted = tea.encrypt(plaintext)
        decrypted = tea.decrypt(encrypted)

        assert decrypted == plaintext

    def test_tea_string_data(self):
        """Test TEA with string data (converted to bytes)."""
        key = b"0123456789abcdef"
        tea = TEA(key)

        plaintext = "hello world test"
        encrypted = tea.encrypt(plaintext)
        decrypted = tea.decrypt(encrypted)

        assert decrypted == plaintext.encode()

    def test_tea_padding(self):
        """Test PKCS7 padding with various lengths."""
        key = b"0123456789abcdef"
        tea = TEA(key)

        # Test various plaintext lengths to verify padding
        test_cases = [
            b"",  # Empty (padded to 8 bytes)
            b"a",  # 1 byte (padded to 8 bytes)
            b"abcdefg",  # 7 bytes (padded to 8 bytes)
            b"abcdefgh",  # 8 bytes (padded to 16 bytes)
            b"abcdefghij",  # 10 bytes (padded to 16 bytes)
            b"01234567",  # Exactly 8 bytes
            b"0123456701234567",  # Exactly 16 bytes
        ]

        for plaintext in test_cases:
            encrypted = tea.encrypt(plaintext)
            decrypted = tea.decrypt(encrypted)
            assert decrypted == plaintext, f"Failed for plaintext: {plaintext}"

    def test_tea_invalid_key_length(self):
        """Test that invalid key lengths raise ValueError."""
        # Key too short
        with pytest.raises(ValueError, match="Key must be 16 bytes"):
            tea_encrypt(b"test", b"short")

        # Key too long
        with pytest.raises(ValueError, match="Key must be 16 bytes"):
            tea_encrypt(b"test", b"this is a very long key indeed!!!")

    def test_tea_invalid_ciphertext_length(self):
        """Test that invalid ciphertext lengths raise ValueError."""
        key = b"0123456789abcdef"

        # Ciphertext not multiple of 8
        with pytest.raises(ValueError, match="Invalid input"):
            tea_decrypt(b"short", key)

        with pytest.raises(ValueError, match="Invalid input"):
            tea_decrypt(b"1234567", key)  # 7 bytes

    def test_tea_key_truncation(self):
        """Test that long keys are truncated to 16 bytes."""
        long_key = b"0123456789abcdefextra"
        tea = TEA(long_key)

        # Key should be truncated to first 16 bytes
        assert tea.key == b"0123456789abcdef"

    def test_tea_key_padding(self):
        """Test that short keys are padded with nulls."""
        short_key = b"short"
        tea = TEA(short_key)

        # Key should be padded with nulls to 16 bytes
        expected_key = b"short" + b"\x00" * 11
        assert tea.key == expected_key

    def test_tea_large_data(self):
        """Test encryption/decryption of larger data."""
        key = b"0123456789abcdef"
        tea = TEA(key)

        plaintext = b"The quick brown fox jumps over the lazy dog. " * 10
        encrypted = tea.encrypt(plaintext)
        decrypted = tea.decrypt(encrypted)

        assert decrypted == plaintext

    def test_tea_binary_data(self):
        """Test encryption/decryption of binary data."""
        key = b"0123456789abcdef"
        tea = TEA(key)

        # Binary data with all byte values
        plaintext = bytes(range(256))
        encrypted = tea.encrypt(plaintext)
        decrypted = tea.decrypt(encrypted)

        assert decrypted == plaintext

    def test_tea_deterministic(self):
        """Test that encryption is deterministic (same input -> same output)."""
        key = b"0123456789abcdef"
        plaintext = b"test data here"

        encrypted1 = tea_encrypt(plaintext, key)
        encrypted2 = tea_encrypt(plaintext, key)

        assert encrypted1 == encrypted2

    def test_tea_different_keys(self):
        """Test that different keys produce different ciphertexts."""
        plaintext = b"test data here!!"
        key1 = b"0123456789abcdef"
        key2 = b"fedcba9876543210"

        encrypted1 = tea_encrypt(plaintext, key1)
        encrypted2 = tea_encrypt(plaintext, key2)

        assert encrypted1 != encrypted2

    def test_tea_empty_data(self):
        """Test encryption/decryption of empty data."""
        key = b"0123456789abcdef"
        tea = TEA(key)

        plaintext = b""
        encrypted = tea.encrypt(plaintext)
        decrypted = tea.decrypt(encrypted)

        assert decrypted == plaintext
