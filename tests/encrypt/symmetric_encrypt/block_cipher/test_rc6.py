"""Tests for RC6 block cipher."""

import pytest

from crypt.encrypt.symmetric_encrypt.block_cipher.rc6 import (
    BLOCK_SIZE,
    decrypt_block,
    encrypt_block,
    key_schedule,
    rc6_cbc_decrypt,
    rc6_cbc_encrypt,
    rc6_ecb_decrypt,
    rc6_ecb_encrypt,
)


class TestRC6:
    """Test RC6 cipher."""

    def test_key_schedule(self):
        """Test key schedule generation."""
        key = b"K" * 32
        subkeys = key_schedule(key)
        # 2*(rounds+2) subkeys for default 20 rounds = 44
        assert len(subkeys) == 44

    def test_encrypt_decrypt_block(self):
        """Test single block encryption and decryption."""
        key = b"SecretKey1234567890123456789012"
        plaintext = b"1234567890123456"

        ciphertext = encrypt_block(plaintext, key)
        assert len(ciphertext) == BLOCK_SIZE

        decrypted = decrypt_block(ciphertext, key)
        assert decrypted == plaintext

    def test_different_keys(self):
        """Test that different keys produce different ciphertexts."""
        plaintext = b"TestData12345678"
        key1 = b"Key1Secret1234567890123456789012"
        key2 = b"Key2Secret6543210987654321098765"

        ciphertext1 = encrypt_block(plaintext, key1)
        ciphertext2 = encrypt_block(plaintext, key2)

        assert ciphertext1 != ciphertext2

    def test_ecb_mode(self):
        """Test ECB mode encryption and decryption."""
        key = b"SecretKey1234567890123456789012"
        plaintext = b"Hello, World! This is a test."

        ciphertext = rc6_ecb_encrypt(plaintext, key)
        decrypted = rc6_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_cbc_mode(self):
        """Test CBC mode encryption and decryption."""
        key = b"SecretKey1234567890123456789012"
        iv = b"RandomIV12345678"
        plaintext = b"Hello, World! This is a test."

        ciphertext = rc6_cbc_encrypt(plaintext, key, iv)
        decrypted = rc6_cbc_decrypt(ciphertext, key, iv)

        assert decrypted == plaintext

    def test_cbc_different_ivs(self):
        """Test that different IVs produce different ciphertexts."""
        key = b"SecretKey1234567890123456789012"
        iv1 = b"RandomIV12345671"
        iv2 = b"RandomIV12345672"
        plaintext = b"Test data for CBC mode"

        ciphertext1 = rc6_cbc_encrypt(plaintext, key, iv1)
        ciphertext2 = rc6_cbc_encrypt(plaintext, key, iv2)

        assert ciphertext1 != ciphertext2

    def test_empty_message(self):
        """Test encryption and decryption of empty message."""
        key = b"SecretKey1234567890123456789012"
        plaintext = b""

        ciphertext = rc6_ecb_encrypt(plaintext, key)
        decrypted = rc6_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_long_message(self):
        """Test encryption and decryption of long message."""
        key = b"SecretKey1234567890123456789012"
        plaintext = b"A" * 1000

        ciphertext = rc6_ecb_encrypt(plaintext, key)
        decrypted = rc6_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_binary_data(self):
        """Test encryption and decryption of binary data."""
        key = b"SecretKey1234567890123456789012"
        plaintext = bytes(range(256))

        ciphertext = rc6_ecb_encrypt(plaintext, key)
        decrypted = rc6_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_invalid_block_size(self):
        """Test that invalid block size raises error."""
        key = b"SecretKey1234567890123456789012"

        with pytest.raises(ValueError):
            encrypt_block(b"short", key)

        with pytest.raises(ValueError):
            decrypt_block(b"short", key)

    def test_cbc_invalid_iv(self):
        """Test that invalid IV raises error."""
        key = b"SecretKey1234567890123456789012"
        iv = b"short"
        plaintext = b"Test data"

        with pytest.raises(ValueError):
            rc6_cbc_encrypt(plaintext, key, iv)

    def test_variable_key_lengths(self):
        """Test that variable key lengths work."""
        plaintext = b"TestData12345678"

        for key_len in [16, 24, 32]:
            key = b"K" * key_len
            ciphertext = encrypt_block(plaintext, key)
            decrypted = decrypt_block(ciphertext, key)
            assert decrypted == plaintext
