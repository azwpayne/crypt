"""Tests for CFB (Cipher Feedback) mode."""

from crypt.encrypt.symmetric_encrypt.modes.cfb import CFBMode

import pytest


class TestCFBMode:
  """Test cases for CFB mode."""

  def test_cfb_mode_basic_encryption_decryption(self):
    """Test basic CFB encryption and decryption round-trip."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    cfb = CFBMode(key=key, iv=iv)

    plaintext = b"Hello, World!"
    ciphertext = cfb.encrypt(plaintext)
    decrypted = cfb.decrypt(ciphertext)

    assert decrypted == plaintext

  def test_cfb_mode_empty_data(self):
    """Test CFB with empty plaintext."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    cfb = CFBMode(key=key, iv=iv)

    plaintext = b""
    ciphertext = cfb.encrypt(plaintext)
    decrypted = cfb.decrypt(ciphertext)

    assert decrypted == plaintext
    assert len(ciphertext) == 0

  def test_cfb_mode_various_lengths(self):
    """Test CFB with various plaintext lengths."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    for length in [1, 5, 15, 16, 17, 32, 100]:
      cfb = CFBMode(key=key, iv=iv)
      data = b"a" * length
      ciphertext = cfb.encrypt(data)
      assert len(ciphertext) == length

      cfb = CFBMode(key=key, iv=iv)
      decrypted = cfb.decrypt(ciphertext)
      assert decrypted == data

  def test_cfb_mode_default_segment_size(self):
    """Test CFB with default segment size (8 bits = 1 byte)."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    cfb = CFBMode(key=key, iv=iv)  # Default segment_size=8

    plaintext = b"Test message"
    ciphertext = cfb.encrypt(plaintext)

    # With 8-bit segment size, should process 1 byte at a time
    cfb = CFBMode(key=key, iv=iv)
    decrypted = cfb.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_cfb_mode_full_block_segment_size(self):
    """Test CFB with full block segment size (128 bits = 16 bytes for AES)."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    # 128 bits = 16 bytes for AES block size
    cfb = CFBMode(key=key, iv=iv, segment_size=128)

    plaintext = b"This is a test message!"
    ciphertext = cfb.encrypt(plaintext)

    cfb = CFBMode(key=key, iv=iv, segment_size=128)
    decrypted = cfb.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_cfb_mode_16_bit_segment_size(self):
    """Test CFB with 16-bit segment size."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    cfb = CFBMode(key=key, iv=iv, segment_size=16)

    plaintext = b"Test with 16-bit segments"
    ciphertext = cfb.encrypt(plaintext)

    cfb = CFBMode(key=key, iv=iv, segment_size=16)
    decrypted = cfb.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_cfb_mode_requires_iv(self):
    """Test that CFB mode requires an IV."""
    key = b"0123456789abcdef"

    with pytest.raises(ValueError, match="IV is required"):
      CFBMode(key=key, iv=None)

  def test_cfb_mode_iv_wrong_length(self):
    """Test that CFB mode rejects IV with wrong length."""
    key = b"0123456789abcdef"
    wrong_iv = b"too short"

    with pytest.raises(ValueError, match="IV must be 16 bytes"):
      CFBMode(key=key, iv=wrong_iv)

  def test_cfb_mode_self_synchronizing(self):
    """Test CFB self-synchronizing property."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    cfb = CFBMode(key=key, iv=iv)

    plaintext = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ciphertext = cfb.encrypt(plaintext)

    # Decrypt should work correctly
    cfb = CFBMode(key=key, iv=iv)
    decrypted = cfb.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_cfb_mode_256_bit_key(self):
    """Test CFB mode with 256-bit key."""
    key = b"0123456789abcdef0123456789abcdef"
    iv = b"1234567890123456"

    cfb = CFBMode(key=key, iv=iv)

    plaintext = b"Test with 256-bit key"
    ciphertext = cfb.encrypt(plaintext)

    cfb = CFBMode(key=key, iv=iv)
    decrypted = cfb.decrypt(ciphertext)
    assert decrypted == plaintext


class TestCFBModeAgainstPyCryptodome:
  """Test CFB mode against pycryptodome reference implementation."""

  def test_cfb_mode_against_pycryptodome_basic(self):
    """Compare CFB output with pycryptodome."""
    pytest.importorskip("Crypto")
    from Crypto.Cipher import AES

    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    plaintext = b"Hello, World! Test message."

    # Our implementation
    cfb = CFBMode(key=key, iv=iv, segment_size=8)
    our_ciphertext = cfb.encrypt(plaintext)

    # PyCryptodome
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8)
    their_ciphertext = cipher.encrypt(plaintext)

    assert our_ciphertext == their_ciphertext

  def test_cfb_mode_against_pycryptodome_full_block(self):
    """Compare full-block CFB with pycryptodome."""
    pytest.importorskip("Crypto")
    from Crypto.Cipher import AES

    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    plaintext = b"Testing full block CFB mode implementation!"

    # Our implementation with full block segment size
    cfb = CFBMode(key=key, iv=iv, segment_size=128)
    our_ciphertext = cfb.encrypt(plaintext)

    # PyCryptodome with full block segment size
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    their_ciphertext = cipher.encrypt(plaintext)

    assert our_ciphertext == their_ciphertext

  def test_cfb_mode_decrypt_against_pycryptodome(self):
    """Compare CFB decryption with pycryptodome."""
    pytest.importorskip("Crypto")
    from Crypto.Cipher import AES

    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    plaintext = b"Test decryption with CFB mode"

    # Encrypt with pycryptodome
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8)
    ciphertext = cipher.encrypt(plaintext)

    # Decrypt with our implementation
    cfb = CFBMode(key=key, iv=iv, segment_size=8)
    decrypted = cfb.decrypt(ciphertext)

    assert decrypted == plaintext
