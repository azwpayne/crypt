"""Tests for CTR mode implementation."""

from crypt.encrypt.symmetric_encrypt.modes import ModeError
from crypt.encrypt.symmetric_encrypt.modes.ctr import CTRMode

import pytest
from Crypto.Cipher import AES as CryptoAES

AES_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NONCE_96 = bytes.fromhex("000102030405060708090a0b")


class TestCTR:
  """Test suite for CTR mode."""

  def test_encrypt_decrypt(self):
    """Test basic encryption and decryption round-trip."""
    key = b"0123456789abcdef"
    # 96-bit nonce + 32-bit counter = 128-bit (16 bytes) block
    nonce = b"123456789012" + b"\x00\x00\x00\x00"
    ctr = CTRMode(key=key, nonce=nonce)

    plaintext = b"Hello, World!"
    ciphertext = ctr.encrypt(plaintext)
    decrypted = ctr.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_against_pycryptodome(self):
    """Compare encryption with Cryptodome.Cipher.AES."""
    key = b"0123456789abcdef"
    # 96-bit nonce + 32-bit counter
    nonce = b"123456789012" + b"\x00\x00\x00\x00"
    plaintext = b"This is a test message for CTR mode."

    # Our implementation
    ctr = CTRMode(key=key, nonce=nonce)
    our_ciphertext = ctr.encrypt(plaintext)

    # PyCryptodome implementation
    cipher = CryptoAES.new(key, CryptoAES.MODE_CTR, nonce=nonce[:12], initial_value=0)
    pycryptodome_ciphertext = cipher.encrypt(plaintext)

    assert our_ciphertext == pycryptodome_ciphertext

    # Also test decryption
    cipher_decrypt = CryptoAES.new(
      key, CryptoAES.MODE_CTR, nonce=nonce[:12], initial_value=0
    )
    pycryptodome_decrypted = cipher_decrypt.decrypt(our_ciphertext)
    assert pycryptodome_decrypted == plaintext

  def test_no_padding(self):
    """Test that any data length works without padding."""
    key = b"0123456789abcdef"
    nonce = b"123456789012" + b"\x00\x00\x00\x00"
    ctr = CTRMode(key=key, nonce=nonce)

    # Test various lengths: 1, 5, 15, 16, 17, 32, 100 bytes
    for length in [1, 5, 15, 16, 17, 32, 100]:
      plaintext = b"a" * length
      ciphertext = ctr.encrypt(plaintext)
      # Ciphertext length should equal plaintext length
      assert len(ciphertext) == length
      decrypted = ctr.decrypt(ciphertext)
      assert decrypted == plaintext

  def test_invalid_nonce_length(self):
    """Test that wrong nonce length raises ValueError."""
    key = b"0123456789abcdef"
    invalid_nonce = b"short"  # Not 16 bytes

    with pytest.raises(ValueError, match="Nonce must be"):
      CTRMode(key=key, nonce=invalid_nonce)

  def test_counter_overflow(self):
    """Test that counter overflow raises ModeError."""
    key = b"0123456789abcdef"
    # Nonce with max counter: 12 bytes prefix + 4 bytes counter = 0xffffffff
    nonce = b"\x00" * 12 + b"\xff\xff\xff\xff"
    ctr = CTRMode(key=key, nonce=nonce)

    # First block should work (counter = 0xffffffff)
    plaintext1 = b"a" * 16
    ciphertext1 = ctr.encrypt(plaintext1)
    assert len(ciphertext1) == 16

    # Second block should overflow (counter would be 0x100000000)
    plaintext2 = b"b" * 16
    with pytest.raises(ModeError, match="Counter overflow"):
      ctr.encrypt(plaintext2)

  def test_stream_cipher_property(self):
    """Test that same plaintext with different nonces produces different ciphertexts."""
    key = b"0123456789abcdef"
    nonce1 = b"123456789012" + b"\x00\x00\x00\x00"
    nonce2 = b"abcdefghijkl" + b"\x00\x00\x00\x00"
    plaintext = b"Same plaintext message"

    ctr1 = CTRMode(key=key, nonce=nonce1)
    ctr2 = CTRMode(key=key, nonce=nonce2)

    ciphertext1 = ctr1.encrypt(plaintext)
    ciphertext2 = ctr2.encrypt(plaintext)

    assert ciphertext1 != ciphertext2

  def test_decrypt_is_same_as_encrypt(self):
    """Test that decrypt is the same function as encrypt (symmetric operation)."""
    key = b"0123456789abcdef"
    nonce = b"123456789012" + b"\x00\x00\x00\x00"
    ctr = CTRMode(key=key, nonce=nonce)

    # encrypt and decrypt should be the same method
    assert ctr.encrypt == ctr.decrypt
    assert ctr.encrypt == ctr.crypt

  def test_empty_data(self):
    """Test encryption and decryption of empty data."""
    key = b"0123456789abcdef"
    nonce = b"123456789012" + b"\x00\x00\x00\x00"
    ctr = CTRMode(key=key, nonce=nonce)

    plaintext = b""
    ciphertext = ctr.encrypt(plaintext)
    assert ciphertext == b""
    decrypted = ctr.decrypt(ciphertext)
    assert decrypted == plaintext
