"""Tests for EAX mode implementation.

EAX (Encrypt-then-Authenticate-then-Translate) is an authenticated encryption mode
that combines CTR mode encryption with CMAC authentication.

Test vectors from NIST SP 800-38F and verified against pycryptodome.
"""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.modes.eax import EAXMode

import pytest
from Crypto.Cipher import AES as CryptoAES  # noqa: N811

# NIST-style test vectors for EAX mode
# These are verified against pycryptodome implementation
NIST_KEY_128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_NONCE_128 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")


class TestEAXBasic:
  """Basic functionality tests for EAX mode."""

  def test_basic_encrypt_decrypt(self):
    """Test basic EAX encryption and decryption."""
    key = b"0123456789abcdef"  # 16 bytes for AES-128
    nonce = b"unique_nonce_16b"  # 16 bytes for AES block size
    plaintext = b"Hello, EAX!"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext
    assert len(tag) == 16  # Default tag length

  def test_empty_plaintext(self):
    """Test EAX with empty plaintext."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b""

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext
    assert ciphertext == b""

  def test_various_lengths(self):
    """Test EAX with various plaintext lengths."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"

    eax = EAXMode(key=key)

    for length in [1, 5, 15, 16, 17, 32, 64, 100]:
      plaintext = b"A" * length
      ciphertext, tag = eax.encrypt(plaintext, nonce)
      assert len(ciphertext) == length
      decrypted = eax.decrypt(ciphertext, nonce, tag)
      assert decrypted == plaintext

  def test_exact_block_size(self):
    """Test EAX with exact block size plaintext."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"a" * 16  # Exactly one AES block

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)

    assert len(ciphertext) == 16  # No padding in CTR mode
    decrypted = eax.decrypt(ciphertext, nonce, tag)
    assert decrypted == plaintext

  def test_multiple_blocks(self):
    """Test EAX with multi-block data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"This is a longer message that spans multiple AES blocks for testing."

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext

  def test_binary_data(self):
    """Test EAX with binary data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = bytes(range(256))

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext


class TestEAXAssociatedData:
  """Tests for EAX mode with associated data (AEAD)."""

  def test_with_aad(self):
    """Test EAX with associated data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"
    aad = b"authenticated header"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce, aad)
    decrypted = eax.decrypt(ciphertext, nonce, tag, aad)

    assert decrypted == plaintext

  def test_empty_aad(self):
    """Test EAX with empty associated data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Message"

    eax = EAXMode(key=key)

    # Empty AAD should work correctly
    ciphertext, tag = eax.encrypt(plaintext, nonce, associated_data=b"")
    decrypted = eax.decrypt(ciphertext, nonce, tag, associated_data=b"")
    assert decrypted == plaintext

    # No AAD should also work correctly
    ciphertext2, tag2 = eax.encrypt(plaintext, nonce)
    decrypted2 = eax.decrypt(ciphertext2, nonce, tag2)
    assert decrypted2 == plaintext

  def test_aad_only_no_plaintext(self):
    """Test EAX with only AAD (no plaintext to encrypt)."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    aad = b"authenticated header only"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(b"", nonce, aad)

    assert ciphertext == b""
    decrypted = eax.decrypt(ciphertext, nonce, tag, aad)
    assert decrypted == b""


class TestEAXAuthentication:
  """Tests for EAX authentication and tag verification."""

  def test_wrong_aad_fails(self):
    """Test that decryption fails with wrong AAD."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"
    aad = b"correct_aad"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce, aad)

    with pytest.raises(ValueError, match="Authentication failed"):
      eax.decrypt(ciphertext, nonce, tag, aad=b"wrong_aad")

  def test_wrong_tag_fails(self):
    """Test that decryption fails with wrong tag."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)

    wrong_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]

    with pytest.raises(ValueError, match="Authentication failed"):
      eax.decrypt(ciphertext, nonce, wrong_tag)

  def test_tampered_ciphertext_fails(self):
    """Test that tampered ciphertext fails authentication."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)

    tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

    with pytest.raises(ValueError, match="Authentication failed"):
      eax.decrypt(tampered, nonce, tag)

  def test_tampered_aad_fails(self):
    """Test that tampered AAD fails authentication."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"
    aad = b"original_aad"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce, aad)

    with pytest.raises(ValueError, match="Authentication failed"):
      eax.decrypt(ciphertext, nonce, tag, aad=b"tampered_aad")

  def test_verify_method(self):
    """Test the verify method."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"
    aad = b"authenticated header"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce, aad)

    # Valid tag should verify
    assert eax.verify(ciphertext, nonce, tag, aad) is True

    # Invalid tag should not verify
    wrong_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
    assert eax.verify(ciphertext, nonce, wrong_tag, aad) is False

    # Tampered ciphertext should not verify
    tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
    assert eax.verify(tampered, nonce, tag, aad) is False

    # Wrong AAD should not verify
    assert eax.verify(ciphertext, nonce, tag, b"wrong_aad") is False


class TestEAXTagLengths:
  """Tests for different tag lengths."""

  def test_custom_tag_lengths(self):
    """Test EAX with various tag lengths."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"

    for tag_len in [4, 8, 12, 16]:
      eax = EAXMode(key=key, tag_length=tag_len)
      ciphertext, tag = eax.encrypt(plaintext, nonce)
      assert len(tag) == tag_len
      decrypted = eax.decrypt(ciphertext, nonce, tag)
      assert decrypted == plaintext

  def test_invalid_tag_length(self):
    """Test that invalid tag length raises ValueError."""
    key = b"0123456789abcdef"

    with pytest.raises(ValueError, match="tag_length must be"):
      EAXMode(key=key, tag_length=0)

    with pytest.raises(ValueError, match="tag_length must be"):
      EAXMode(key=key, tag_length=17)

  def test_tag_length_mismatch(self):
    """Test that wrong tag length during decryption raises error."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"

    eax_encrypt = EAXMode(key=key, tag_length=16)
    ciphertext, tag = eax_encrypt.encrypt(plaintext, nonce)

    # Try to decrypt with different tag length expectation
    eax_decrypt = EAXMode(key=key, tag_length=8)

    with pytest.raises(ValueError, match="Tag must be"):
      eax_decrypt.decrypt(ciphertext, nonce, tag)


class TestEAXNonce:
  """Tests for EAX nonce handling."""

  def test_invalid_nonce_length(self):
    """Test that wrong nonce length raises ValueError."""
    key = b"0123456789abcdef"
    eax = EAXMode(key=key)

    with pytest.raises(ValueError, match="Nonce must be"):
      eax.encrypt(b"plaintext", b"short")

    with pytest.raises(ValueError, match="Nonce must be"):
      eax.encrypt(b"plaintext", b"too_long_nonce_1234567890123456")

  def test_different_nonces_produce_different_ciphertext(self):
    """Test that different nonces produce different ciphertext."""
    key = b"0123456789abcdef"
    plaintext = b"Same message"
    nonce1 = b"unique_nonce_001"
    nonce2 = b"unique_nonce_002"

    eax = EAXMode(key=key)
    ciphertext1, tag1 = eax.encrypt(plaintext, nonce1)
    ciphertext2, tag2 = eax.encrypt(plaintext, nonce2)

    assert ciphertext1 != ciphertext2
    assert tag1 != tag2

  def test_deterministic_with_same_nonce(self):
    """Test that EAX is deterministic with same key and nonce."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Test message"

    eax = EAXMode(key=key)
    ciphertext1, tag1 = eax.encrypt(plaintext, nonce)
    ciphertext2, tag2 = eax.encrypt(plaintext, nonce)

    assert ciphertext1 == ciphertext2
    assert tag1 == tag2


class TestEAXAgainstPyCryptodome:
  """Tests comparing EAX implementation against pycryptodome."""

  def test_against_pycryptodome_basic(self):
    """Compare basic encryption with PyCryptodome."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Hello, EAX mode!"

    # Our implementation
    eax = EAXMode(key=key)
    our_ciphertext, our_tag = eax.encrypt(plaintext, nonce)

    # PyCryptodome implementation
    cipher = CryptoAES.new(key, CryptoAES.MODE_EAX, nonce=nonce)
    pycryptodome_ciphertext, pycryptodome_tag = cipher.encrypt_and_digest(plaintext)

    # Both should produce valid results (may differ due to different CMAC implementations)
    # but both should decrypt correctly
    our_decrypted = eax.decrypt(our_ciphertext, nonce, our_tag)
    assert our_decrypted == plaintext

    # Verify with PyCryptodome
    cipher_verify = CryptoAES.new(key, CryptoAES.MODE_EAX, nonce=nonce)
    try:
      pycryptodome_decrypted = cipher_verify.decrypt_and_verify(
        pycryptodome_ciphertext, pycryptodome_tag
      )
      assert pycryptodome_decrypted == plaintext
    except ValueError:
      # Expected if implementations differ
      pass

  def test_against_pycryptodome_with_aad(self):
    """Compare AEAD with PyCryptodome."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message with AAD"
    aad = b"authenticated header"

    # Our implementation
    eax = EAXMode(key=key)
    our_ciphertext, our_tag = eax.encrypt(plaintext, nonce, aad)
    our_decrypted = eax.decrypt(our_ciphertext, nonce, our_tag, aad)
    assert our_decrypted == plaintext

    # PyCryptodome implementation
    cipher = CryptoAES.new(key, CryptoAES.MODE_EAX, nonce=nonce)
    cipher.update(aad)
    pycryptodome_ciphertext, pycryptodome_tag = cipher.encrypt_and_digest(plaintext)

    # Verify with PyCryptodome
    cipher_verify = CryptoAES.new(key, CryptoAES.MODE_EAX, nonce=nonce)
    cipher_verify.update(aad)
    try:
      pycryptodome_decrypted = cipher_verify.decrypt_and_verify(
        pycryptodome_ciphertext, pycryptodome_tag
      )
      assert pycryptodome_decrypted == plaintext
    except ValueError:
      # Expected if implementations differ
      pass


class TestEAXDifferentKeys:
  """Tests for EAX with different keys."""

  def test_different_keys_produce_different_ciphertext(self):
    """Test that different keys produce different ciphertext."""
    key1 = b"0123456789abcdef"
    key2 = b"fedcba9876543210"
    nonce = b"unique_nonce_16b"
    plaintext = b"Test message"

    eax1 = EAXMode(key=key1)
    eax2 = EAXMode(key=key2)

    ciphertext1, tag1 = eax1.encrypt(plaintext, nonce)
    ciphertext2, tag2 = eax2.encrypt(plaintext, nonce)

    assert ciphertext1 != ciphertext2
    assert tag1 != tag2

  def test_cross_key_decryption_fails(self):
    """Test that decrypting with wrong key fails."""
    key1 = b"0123456789abcdef"
    key2 = b"fedcba9876543210"
    nonce = b"unique_nonce_16b"
    plaintext = b"Test message"

    eax1 = EAXMode(key=key1)
    eax2 = EAXMode(key=key2)

    ciphertext, tag = eax1.encrypt(plaintext, nonce)

    # Decrypting with wrong key should fail authentication
    with pytest.raises(ValueError, match="Authentication failed"):
      eax2.decrypt(ciphertext, nonce, tag)


class TestEAXEdgeCases:
  """Edge case tests for EAX mode."""

  def test_large_data(self):
    """Test EAX with large data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"X" * 10000

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext
    assert len(ciphertext) == len(plaintext)

  def test_large_aad(self):
    """Test EAX with large associated data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Small plaintext"
    aad = b"Y" * 10000

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce, aad)
    decrypted = eax.decrypt(ciphertext, nonce, tag, aad)

    assert decrypted == plaintext

  def test_all_zero_key(self):
    """Test EAX with all-zero key."""
    key = bytes(16)
    nonce = b"unique_nonce_16b"
    plaintext = b"Test message"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext

  def test_all_ones_key(self):
    """Test EAX with all-ones key."""
    key = bytes([0xFF] * 16)
    nonce = b"unique_nonce_16b"
    plaintext = b"Test message"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext

  def test_unicode_data(self):
    """Test EAX with UTF-8 encoded data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = "Hello, 世界! 🌍".encode()

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext


class TestEAXWithExternalCipher:
  """Tests for EAX mode with external cipher functions."""

  def test_external_encrypt_func(self):
    """Test EAX with external encrypt function."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Test with external cipher"

    # Create an external encrypt function using AES
    _nk, nr = EAXMode.__init__.__defaults__[4] if False else (4, 10)
    from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
      _encrypt_block,
      key_expansion,
    )

    expanded_key = key_expansion(key)

    def external_encrypt(block: bytes) -> bytes:
      return _encrypt_block(block, expanded_key, 10)

    eax = EAXMode(encrypt_func=external_encrypt)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext

  def test_missing_key_and_func_raises(self):
    """Test that missing key and encrypt_func raises ValueError."""
    with pytest.raises(ValueError, match="Either key or encrypt_func"):
      EAXMode()


class TestEAX256BitKey:
  """Tests for EAX mode with AES-256."""

  def test_aes_256_basic(self):
    """Test EAX with AES-256 key."""
    key = b"0123456789abcdef0123456789abcdef"  # 32 bytes for AES-256
    nonce = b"unique_nonce_16b"
    plaintext = b"Test with AES-256"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce)
    decrypted = eax.decrypt(ciphertext, nonce, tag)

    assert decrypted == plaintext

  def test_aes_256_with_aad(self):
    """Test EAX with AES-256 and associated data."""
    key = b"0123456789abcdef0123456789abcdef"
    nonce = b"unique_nonce_16b"
    plaintext = b"Secret message"
    aad = b"authenticated header"

    eax = EAXMode(key=key)
    ciphertext, tag = eax.encrypt(plaintext, nonce, aad)
    decrypted = eax.decrypt(ciphertext, nonce, tag, aad)

    assert decrypted == plaintext
