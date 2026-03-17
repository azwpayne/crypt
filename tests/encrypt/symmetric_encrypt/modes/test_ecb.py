"""Tests for ECB mode implementation."""

import warnings
from crypt.encrypt.symmetric_encrypt.modes.ecb import ECBMode

import pytest

AES_KEY = b"0123456789abcdef"


@pytest.fixture
def ecb_mode():
  """Create an ECB mode instance with AES."""
  with warnings.catch_warnings():
    warnings.simplefilter("ignore", UserWarning)
    return ECBMode(key=AES_KEY)


class TestECB:
  """Test suite for ECB mode."""

  def test_ecb_warning(self):
    """Test that ECB mode emits a security warning on initialization."""
    with pytest.warns(UserWarning, match="ECB mode is not secure"):
      ECBMode(key=AES_KEY)

  def test_encrypt_decrypt(self, ecb_mode):
    """Test basic encryption and decryption round-trip."""
    plaintext = b"Hello, World!"
    ciphertext = ecb_mode.encrypt(plaintext)
    decrypted = ecb_mode.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_empty_data(self, ecb_mode):
    """Test encryption and decryption of empty data."""
    plaintext = b""
    ciphertext = ecb_mode.encrypt(plaintext)
    decrypted = ecb_mode.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_exact_block(self, ecb_mode):
    """Test that exact block size adds padding."""
    plaintext = b"a" * 16  # Exactly one AES block
    ciphertext = ecb_mode.encrypt(plaintext)
    # Should be 2 blocks due to PKCS7 padding
    assert len(ciphertext) == 32
    decrypted = ecb_mode.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_multiple_blocks(self, ecb_mode):
    """Test encryption and decryption of multi-block data."""
    plaintext = b"This is a longer message that spans multiple AES blocks."
    ciphertext = ecb_mode.encrypt(plaintext)
    decrypted = ecb_mode.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_invalid_ciphertext_length(self, ecb_mode):
    """Test that invalid ciphertext length raises ValueError."""
    with pytest.raises(ValueError, match="multiple of block_size"):
      ecb_mode.decrypt(b"short")  # Not a multiple of 16

  def test_binary_data(self, ecb_mode):
    """Test encryption and decryption of binary data."""
    plaintext = bytes(range(256))
    ciphertext = ecb_mode.encrypt(plaintext)
    decrypted = ecb_mode.decrypt(ciphertext)
    assert decrypted == plaintext
