"""Tests for PRESENT block cipher."""

from crypt.encrypt.symmetric_encrypt.block_cipher.present import (
  BLOCK_SIZE,
  decrypt_block,
  encrypt_block,
  key_schedule,
  present_cbc_decrypt,
  present_cbc_encrypt,
  present_ecb_decrypt,
  present_ecb_encrypt,
)

import pytest


class TestPresent:
  """Test PRESENT cipher."""

  def test_key_schedule_80(self):
    """Test key schedule generation for 80-bit key."""
    key = b"K" * 10  # 80 bits
    round_keys = key_schedule(key)
    assert len(round_keys) == 32

  def test_key_schedule_128(self):
    """Test key schedule generation for 128-bit key."""
    key = b"K" * 16  # 128 bits
    round_keys = key_schedule(key)
    assert len(round_keys) == 32

  def test_encrypt_decrypt_block_80(self):
    """Test single block encryption and decryption with 80-bit key."""
    key = b"SecretKey1"  # 10 bytes = 80 bits
    plaintext = b"12345678"

    ciphertext = encrypt_block(plaintext, key)
    assert len(ciphertext) == BLOCK_SIZE

    decrypted = decrypt_block(ciphertext, key)
    assert decrypted == plaintext

  def test_encrypt_decrypt_block_128(self):
    """Test single block encryption and decryption with 128-bit key."""
    key = b"SecretKey1234567"  # 16 bytes = 128 bits
    plaintext = b"12345678"

    ciphertext = encrypt_block(plaintext, key)
    assert len(ciphertext) == BLOCK_SIZE

    decrypted = decrypt_block(ciphertext, key)
    assert decrypted == plaintext

  def test_different_keys(self):
    """Test that different keys produce different ciphertexts."""
    plaintext = b"TestData"
    key1 = b"Key1Test" + b"\x00" * 2
    key2 = b"Key2Test" + b"\x00" * 2

    ciphertext1 = encrypt_block(plaintext, key1)
    ciphertext2 = encrypt_block(plaintext, key2)

    assert ciphertext1 != ciphertext2

  def test_ecb_mode(self):
    """Test ECB mode encryption and decryption."""
    key = b"SecretKey1"
    plaintext = b"Hello, World! This is a test."

    ciphertext = present_ecb_encrypt(plaintext, key)
    decrypted = present_ecb_decrypt(ciphertext, key)

    assert decrypted == plaintext

  def test_cbc_mode(self):
    """Test CBC mode encryption and decryption."""
    key = b"SecretKey1"
    iv = b"RandomIV"
    plaintext = b"Hello, World! This is a test."

    ciphertext = present_cbc_encrypt(plaintext, key, iv)
    decrypted = present_cbc_decrypt(ciphertext, key, iv)

    assert decrypted == plaintext

  def test_cbc_different_ivs(self):
    """Test that different IVs produce different ciphertexts."""
    key = b"SecretKey1"
    iv1 = b"RandomI1"
    iv2 = b"RandomI2"
    plaintext = b"Test data for CBC mode"

    ciphertext1 = present_cbc_encrypt(plaintext, key, iv1)
    ciphertext2 = present_cbc_encrypt(plaintext, key, iv2)

    assert ciphertext1 != ciphertext2

  def test_empty_message(self):
    """Test encryption and decryption of empty message."""
    key = b"SecretKey1"
    plaintext = b""

    ciphertext = present_ecb_encrypt(plaintext, key)
    decrypted = present_ecb_decrypt(ciphertext, key)

    assert decrypted == plaintext

  def test_long_message(self):
    """Test encryption and decryption of long message."""
    key = b"SecretKey1"
    plaintext = b"A" * 1000

    ciphertext = present_ecb_encrypt(plaintext, key)
    decrypted = present_ecb_decrypt(ciphertext, key)

    assert decrypted == plaintext

  def test_binary_data(self):
    """Test encryption and decryption of binary data."""
    key = b"SecretKey1"
    plaintext = bytes(range(256))

    ciphertext = present_ecb_encrypt(plaintext, key)
    decrypted = present_ecb_decrypt(ciphertext, key)

    assert decrypted == plaintext

  def test_invalid_block_size(self):
    """Test that invalid block size raises error."""
    key = b"SecretKey1"

    with pytest.raises(ValueError, match="Block must be"):
      encrypt_block(b"short", key)

    with pytest.raises(ValueError, match="Block must be"):
      decrypt_block(b"short", key)

  def test_invalid_key_size(self):
    """Test that invalid key size raises error."""
    with pytest.raises(ValueError, match="Key must be"):
      key_schedule(b"short")

    with pytest.raises(ValueError, match="Key must be"):
      encrypt_block(b"12345678", b"short")

  def test_cbc_invalid_iv(self):
    """Test that invalid IV raises error."""
    key = b"SecretKey1"
    iv = b"short"
    plaintext = b"Test data"

    with pytest.raises(ValueError, match="IV must be"):
      present_cbc_encrypt(plaintext, key, iv)
