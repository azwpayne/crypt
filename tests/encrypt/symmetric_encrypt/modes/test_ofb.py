"""Tests for OFB (Output Feedback) mode."""

from crypt.encrypt.symmetric_encrypt.modes.ofb import OFBMode

import pytest


class TestOFBMode:
  """Test cases for OFB mode."""

  def test_ofb_mode_basic_encryption_decryption(self):
    """Test basic OFB encryption and decryption round-trip."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    ofb = OFBMode(key=key, iv=iv)

    plaintext = b"Hello, World!"
    ciphertext = ofb.encrypt(plaintext)
    decrypted = ofb.decrypt(ciphertext)

    assert decrypted == plaintext

  def test_ofb_mode_empty_data(self):
    """Test OFB with empty plaintext."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    ofb = OFBMode(key=key, iv=iv)

    plaintext = b""
    ciphertext = ofb.encrypt(plaintext)
    decrypted = ofb.decrypt(ciphertext)

    assert decrypted == plaintext
    assert len(ciphertext) == 0

  def test_ofb_mode_various_lengths(self):
    """Test OFB with various plaintext lengths."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    for length in [1, 5, 15, 16, 17, 32, 100]:
      ofb = OFBMode(key=key, iv=iv)
      data = b"a" * length
      ciphertext = ofb.encrypt(data)
      assert len(ciphertext) == length

      ofb = OFBMode(key=key, iv=iv)
      decrypted = ofb.decrypt(ciphertext)
      assert decrypted == data

  def test_ofb_mode_no_error_propagation(self):
    """Test that OFB mode has no error propagation in ciphertext."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"

    ofb = OFBMode(key=key, iv=iv)

    plaintext = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ciphertext = ofb.encrypt(plaintext)

    # Corrupt one byte in ciphertext
    corrupted = bytearray(ciphertext)
    corrupted[5] ^= 0xFF

    # Decrypt corrupted ciphertext
    ofb = OFBMode(key=key, iv=iv)
    decrypted = ofb.decrypt(bytes(corrupted))

    # Only the corresponding plaintext byte should be affected
    assert decrypted[5] != plaintext[5]
    assert decrypted[:5] == plaintext[:5]
    assert decrypted[6:] == plaintext[6:]

  def test_ofb_mode_requires_iv(self):
    """Test that OFB mode requires an IV."""
    key = b"0123456789abcdef"

    with pytest.raises(ValueError, match="IV is required"):
      OFBMode(key=key, iv=None)

  def test_ofb_mode_iv_wrong_length(self):
    """Test that OFB mode rejects IV with wrong length."""
    key = b"0123456789abcdef"
    wrong_iv = b"too short"

    with pytest.raises(ValueError, match="IV must be 16 bytes"):
      OFBMode(key=key, iv=wrong_iv)

  def test_ofb_mode_256_bit_key(self):
    """Test OFB mode with 256-bit key."""
    key = b"0123456789abcdef0123456789abcdef"
    iv = b"1234567890123456"

    ofb = OFBMode(key=key, iv=iv)

    plaintext = b"Test with 256-bit key"
    ciphertext = ofb.encrypt(plaintext)

    ofb = OFBMode(key=key, iv=iv)
    decrypted = ofb.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_ofb_mode_different_ivs_produce_different_ciphertext(self):
    """Test that different IVs produce different ciphertext."""
    key = b"0123456789abcdef"
    iv1 = b"1234567890123456"
    iv2 = b"abcdefghijklmnop"

    plaintext = b"Same plaintext"

    ofb1 = OFBMode(key=key, iv=iv1)
    ciphertext1 = ofb1.encrypt(plaintext)

    ofb2 = OFBMode(key=key, iv=iv2)
    ciphertext2 = ofb2.encrypt(plaintext)

    assert ciphertext1 != ciphertext2


class TestOFBModeAgainstPyCryptodome:
  """Test OFB mode against pycryptodome reference implementation."""

  def test_ofb_mode_against_pycryptodome_basic(self):
    """Compare OFB output with pycryptodome."""
    pytest.importorskip("Crypto")
    from Crypto.Cipher import AES

    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    plaintext = b"Hello, World! Test message."

    # Our implementation
    ofb = OFBMode(key=key, iv=iv)
    our_ciphertext = ofb.encrypt(plaintext)

    # PyCryptodome
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    their_ciphertext = cipher.encrypt(plaintext)

    assert our_ciphertext == their_ciphertext

  def test_ofb_mode_decrypt_against_pycryptodome(self):
    """Compare OFB decryption with pycryptodome."""
    pytest.importorskip("Crypto")
    from Crypto.Cipher import AES

    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    plaintext = b"Test decryption with OFB mode"

    # Encrypt with pycryptodome
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    ciphertext = cipher.encrypt(plaintext)

    # Decrypt with our implementation
    ofb = OFBMode(key=key, iv=iv)
    decrypted = ofb.decrypt(ciphertext)

    assert decrypted == plaintext
