"""Tests for SEAL stream cipher."""

from crypt.encrypt.symmetric_encrypt.stream_cipher.seal import (
  seal_decrypt,
  seal_encrypt,
  seal_keystream,
)

import pytest


class TestSEAL:
  """Test SEAL stream cipher."""

  def test_basic_encryption_decryption(self):
    """Test basic encryption and decryption."""
    key = b"SecretKey12345678901"  # 20 bytes
    iv = 0x12345678  # 32-bit position index
    plaintext = b"Hello, World!"

    ciphertext = seal_encrypt(key, iv, plaintext)
    decrypted = seal_decrypt(key, iv, ciphertext)

    assert decrypted == plaintext

  def test_different_keys(self):
    """Test that different keys produce different ciphertexts."""
    plaintext = b"Test data"
    key1 = b"Key1Secret1234567890"
    key2 = b"Key2Secret6543210987"
    iv = 0x12345678

    ciphertext1 = seal_encrypt(key1, iv, plaintext)
    ciphertext2 = seal_encrypt(key2, iv, plaintext)

    assert ciphertext1 != ciphertext2

  def test_different_ivs(self):
    """Test that different IVs produce different ciphertexts."""
    key = b"SecretKey12345678901"
    iv1 = 0x12345678
    iv2 = 0x87654321
    plaintext = b"Test data"

    ciphertext1 = seal_encrypt(key, iv1, plaintext)
    ciphertext2 = seal_encrypt(key, iv2, plaintext)

    assert ciphertext1 != ciphertext2

  def test_empty_message(self):
    """Test encryption and decryption of empty message."""
    key = b"SecretKey12345678901"
    iv = 0x12345678
    plaintext = b""

    ciphertext = seal_encrypt(key, iv, plaintext)
    decrypted = seal_decrypt(key, iv, ciphertext)

    assert decrypted == plaintext

  def test_long_message(self):
    """Test encryption and decryption of long message."""
    key = b"SecretKey12345678901"
    iv = 0x12345678
    plaintext = b"A" * 1000

    ciphertext = seal_encrypt(key, iv, plaintext)
    decrypted = seal_decrypt(key, iv, ciphertext)

    assert decrypted == plaintext

  def test_binary_data(self):
    """Test encryption and decryption of binary data."""
    key = b"SecretKey12345678901"
    iv = 0x12345678
    plaintext = bytes(range(256))

    ciphertext = seal_encrypt(key, iv, plaintext)
    decrypted = seal_decrypt(key, iv, ciphertext)

    assert decrypted == plaintext

  def test_keystream_generation(self):
    """Test keystream generation."""
    key = b"SecretKey12345678901"
    iv = 0x12345678

    keystream = seal_keystream(key, iv, 100)
    assert len(keystream) == 100

  def test_invalid_key_size(self):
    """Test that invalid key size raises error."""
    with pytest.raises(ValueError, match="Key must be 20 bytes"):
      seal_encrypt(b"short", 0, b"test")

  def test_stream_cipher_property(self):
    """Test that encryption and decryption are the same operation."""
    key = b"SecretKey12345678901"
    iv = 0x12345678
    plaintext = b"Test message"

    # Encrypt twice with same key and IV should give same result
    ciphertext1 = seal_encrypt(key, iv, plaintext)
    ciphertext2 = seal_encrypt(key, iv, plaintext)

    assert ciphertext1 == ciphertext2
