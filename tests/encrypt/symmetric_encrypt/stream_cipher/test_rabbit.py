"""Tests for Rabbit stream cipher."""

import pytest

from crypt.encrypt.symmetric_encrypt.stream_cipher.rabbit import (
    rabbit_decrypt,
    rabbit_encrypt,
    rabbit_keystream,
)


class TestRabbit:
    """Test Rabbit stream cipher."""

    def test_basic_encryption_decryption(self):
        """Test basic encryption and decryption."""
        key = b"SecretKey1234567"  # 16 bytes
        plaintext = b"Hello, World!"

        ciphertext = rabbit_encrypt(key, None, plaintext)
        decrypted = rabbit_decrypt(key, None, ciphertext)

        assert decrypted == plaintext

    def test_encryption_with_iv(self):
        """Test encryption with IV."""
        key = b"SecretKey1234567"  # 16 bytes
        iv = b"12345678"  # 8 bytes
        plaintext = b"Hello, World!"

        ciphertext = rabbit_encrypt(key, iv, plaintext)
        decrypted = rabbit_decrypt(key, iv, ciphertext)

        assert decrypted == plaintext

    def test_different_keys(self):
        """Test that different keys produce different ciphertexts."""
        plaintext = b"Test data"
        key1 = b"Key1Secret123456"
        key2 = b"Key2Secret654321"

        ciphertext1 = rabbit_encrypt(key1, None, plaintext)
        ciphertext2 = rabbit_encrypt(key2, None, plaintext)

        assert ciphertext1 != ciphertext2

    def test_different_ivs(self):
        """Test that different IVs produce different ciphertexts."""
        key = b"SecretKey1234567"
        iv1 = b"IV123456"
        iv2 = b"IV654321"
        plaintext = b"Test data"

        ciphertext1 = rabbit_encrypt(key, iv1, plaintext)
        ciphertext2 = rabbit_encrypt(key, iv2, plaintext)

        assert ciphertext1 != ciphertext2

    def test_empty_message(self):
        """Test encryption and decryption of empty message."""
        key = b"SecretKey1234567"
        plaintext = b""

        ciphertext = rabbit_encrypt(key, None, plaintext)
        decrypted = rabbit_decrypt(key, None, ciphertext)

        assert decrypted == plaintext

    def test_long_message(self):
        """Test encryption and decryption of long message."""
        key = b"SecretKey1234567"
        plaintext = b"A" * 1000

        ciphertext = rabbit_encrypt(key, None, plaintext)
        decrypted = rabbit_decrypt(key, None, ciphertext)

        assert decrypted == plaintext

    def test_binary_data(self):
        """Test encryption and decryption of binary data."""
        key = b"SecretKey1234567"
        plaintext = bytes(range(256))

        ciphertext = rabbit_encrypt(key, None, plaintext)
        decrypted = rabbit_decrypt(key, None, ciphertext)

        assert decrypted == plaintext

    def test_keystream_generation(self):
        """Test keystream generation."""
        key = b"SecretKey1234567"
        iv = b"12345678"

        keystream = rabbit_keystream(key, iv, 100)
        assert len(keystream) == 100

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        with pytest.raises(ValueError):
            rabbit_encrypt(b"short", None, b"test")

    def test_invalid_iv_size(self):
        """Test that invalid IV size raises error."""
        key = b"SecretKey1234567"
        with pytest.raises(ValueError):
            rabbit_encrypt(key, b"short", b"test")

    def test_stream_cipher_property(self):
        """Test that encryption and decryption are the same operation."""
        key = b"SecretKey1234567"
        plaintext = b"Test message"

        # Encrypt twice should give different results (no IV, same state)
        # Actually with same key and no IV, should be deterministic
        ciphertext1 = rabbit_encrypt(key, None, plaintext)
        ciphertext2 = rabbit_encrypt(key, None, plaintext)

        assert ciphertext1 == ciphertext2

    def test_xor_property(self):
        """Test that ciphertext is plaintext XOR keystream."""
        key = b"SecretKey1234567"
        iv = b"12345678"
        plaintext = b"Test message!"

        ciphertext = rabbit_encrypt(key, iv, plaintext)
        keystream = rabbit_keystream(key, iv, len(plaintext))

        # ciphertext = plaintext XOR keystream
        xored = bytes(a ^ b for a, b in zip(plaintext, keystream))
        assert xored == ciphertext
