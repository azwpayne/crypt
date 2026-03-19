"""Tests for CBC mode implementation."""

from crypt.encrypt.symmetric_encrypt.modes.cbc import CBCMode

import pytest
from Crypto.Cipher import AES as CRYPTO_AES

AES_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_PLAINTEXT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
NIST_CIPHERTEXT = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")


@pytest.fixture
def cbc_mode():
  """Create a CBC mode instance with AES."""
  return CBCMode(key=AES_KEY, iv=NIST_IV)


class TestCBC:
  """Test suite for CBC mode."""

  def test_nist_vector(self, cbc_mode):
    """Test against NIST SP 800-38A test vector."""
    # NIST test vector: single block encryption
    ciphertext = cbc_mode.encrypt(NIST_PLAINTEXT)
    # First block should match NIST expected ciphertext
    assert ciphertext[:16] == NIST_CIPHERTEXT

  def test_encrypt_decrypt(self):
    """Test basic encryption and decryption round-trip."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    cbc = CBCMode(key=key, iv=iv)

    plaintext = b"Hello, World!"
    ciphertext = cbc.encrypt(plaintext)
    decrypted = cbc.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_against_pycryptodome(self):
    """Compare encryption with Cryptodome.Cipher.AES."""
    from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import pad

    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    plaintext = b"This is a test message for CBC mode."

    # Our implementation (handles padding internally)
    cbc = CBCMode(key=key, iv=iv)
    our_ciphertext = cbc.encrypt(plaintext)

    # PyCryptodome implementation (requires padded plaintext)
    padded_plaintext = pad(plaintext, 16)
    cipher = CRYPTO_AES.new(key, CRYPTO_AES.MODE_CBC, iv=iv)
    pycryptodome_ciphertext = cipher.encrypt(padded_plaintext)

    assert our_ciphertext == pycryptodome_ciphertext

    # Also test decryption - PyCryptodome returns padded plaintext
    cipher_decrypt = CRYPTO_AES.new(key, CRYPTO_AES.MODE_CBC, iv=iv)
    pycryptodome_padded = cipher_decrypt.decrypt(our_ciphertext)
    # Remove padding to compare
    from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import unpad

    pycryptodome_decrypted = unpad(pycryptodome_padded, 16)
    assert pycryptodome_decrypted == plaintext

  def test_invalid_iv_length(self):
    """Test that wrong IV length raises ValueError."""
    key = b"0123456789abcdef"
    invalid_iv = b"short"  # Not 16 bytes

    with pytest.raises(ValueError, match="IV must be"):
      CBCMode(key=key, iv=invalid_iv)

  def test_invalid_ciphertext_length(self):
    """Test that wrong ciphertext length raises ValueError."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    cbc = CBCMode(key=key, iv=iv)

    with pytest.raises(ValueError, match="multiple of block_size"):
      cbc.decrypt(b"short")  # Not a multiple of 16

  def test_chaining(self):
    """Verify identical plaintext blocks produce different ciphertext."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    cbc = CBCMode(key=key, iv=iv)

    # Two identical blocks
    plaintext = b"a" * 32  # Two 16-byte blocks
    ciphertext = cbc.encrypt(plaintext)

    # Split into blocks
    block1 = ciphertext[:16]
    block2 = ciphertext[16:32]

    # Due to CBC chaining, identical plaintext blocks should produce
    # different ciphertext blocks
    assert block1 != block2

  def test_empty_data(self):
    """Test encryption and decryption of empty data."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    cbc = CBCMode(key=key, iv=iv)

    plaintext = b""
    ciphertext = cbc.encrypt(plaintext)
    decrypted = cbc.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_exact_block_size(self):
    """Test that exact block size adds padding."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    cbc = CBCMode(key=key, iv=iv)

    plaintext = b"a" * 16  # Exactly one AES block
    ciphertext = cbc.encrypt(plaintext)
    # Should be 2 blocks due to PKCS7 padding
    assert len(ciphertext) == 32
    decrypted = cbc.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_multiple_blocks(self):
    """Test encryption and decryption of multi-block data."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    cbc = CBCMode(key=key, iv=iv)

    plaintext = b"This is a longer message that spans multiple AES blocks."
    ciphertext = cbc.encrypt(plaintext)
    decrypted = cbc.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_binary_data(self):
    """Test encryption and decryption of binary data."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    cbc = CBCMode(key=key, iv=iv)

    plaintext = bytes(range(256))
    ciphertext = cbc.encrypt(plaintext)
    decrypted = cbc.decrypt(ciphertext)
    assert decrypted == plaintext

  def test_different_ivs_produce_different_ciphertext(self):
    """Test that different IVs produce different ciphertext for same plaintext."""
    key = b"0123456789abcdef"
    iv1 = b"1234567890123456"
    iv2 = b"abcdefghijklmnop"
    plaintext = b"Same plaintext message"

    cbc1 = CBCMode(key=key, iv=iv1)
    cbc2 = CBCMode(key=key, iv=iv2)

    ciphertext1 = cbc1.encrypt(plaintext)
    ciphertext2 = cbc2.encrypt(plaintext)

    assert ciphertext1 != ciphertext2
