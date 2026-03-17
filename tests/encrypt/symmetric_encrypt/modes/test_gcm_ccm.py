# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_gcm_ccm.py
# @time    : 2026/3/17
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for GCM and CCM authenticated encryption modes

"""
Test suite for GCM (Galois/Counter Mode) and CCM (Counter with CBC-MAC) AEAD modes.

These modes provide both confidentiality and authenticity.
Tests include:
- Basic encryption/decryption
- Authentication tag verification
- Additional Authenticated Data (AAD) handling
- Tampering detection
- Various data lengths
"""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.ccm import (
  ccm_decrypt,
  ccm_encrypt,
)
from crypt.encrypt.symmetric_encrypt.gcm import (
  _generate_keystream,
  _xor_bytes,
  gcm_decrypt,
  gcm_encrypt,
)


class TestGCM:
  """Test cases for GCM mode."""

  def test_gcm_basic_encrypt_decrypt(self):
    """Test basic GCM encryption and decryption."""
    key = b"0123456789abcdef"  # 16 bytes
    iv = b"unique_iv_1234"  # 14 bytes
    plaintext = b"Hello, GCM!"

    ciphertext, tag = gcm_encrypt(key, iv, plaintext)
    decrypted = gcm_decrypt(key, iv, ciphertext, tag)

    assert decrypted == plaintext
    assert len(tag) == 16  # Default tag length

  def test_gcm_with_aad(self):
    """Test GCM with Additional Authenticated Data."""
    key = b"0123456789abcdef"
    iv = b"unique_iv_1234"
    plaintext = b"Secret message"
    aad = b"authenticated header"

    ciphertext, tag = gcm_encrypt(key, iv, plaintext, aad=aad)
    decrypted = gcm_decrypt(key, iv, ciphertext, tag, aad=aad)

    assert decrypted == plaintext

  def test_gcm_wrong_aad_fails(self):
    """Test that decryption fails with wrong AAD."""
    key = b"0123456789abcdef"
    iv = b"unique_iv_1234"
    plaintext = b"Secret message"
    aad = b"correct_aad"

    ciphertext, tag = gcm_encrypt(key, iv, plaintext, aad=aad)
    # Try to decrypt with wrong AAD
    decrypted = gcm_decrypt(key, iv, ciphertext, tag, aad=b"wrong_aad")

    assert decrypted is None

  def test_gcm_tampered_ciphertext_fails(self):
    """Test that tampered ciphertext fails authentication."""
    key = b"0123456789abcdef"
    iv = b"unique_iv_1234"
    plaintext = b"Secret message"

    ciphertext, tag = gcm_encrypt(key, iv, plaintext)

    # Tamper with ciphertext
    tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

    decrypted = gcm_decrypt(key, iv, tampered, tag)
    assert decrypted is None

  def test_gcm_tampered_tag_fails(self):
    """Test that tampered tag fails authentication."""
    key = b"0123456789abcdef"
    iv = b"unique_iv_1234"
    plaintext = b"Secret message"

    ciphertext, tag = gcm_encrypt(key, iv, plaintext)

    # Tamper with tag
    tampered_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]

    decrypted = gcm_decrypt(key, iv, ciphertext, tampered_tag)
    assert decrypted is None

  def test_gcm_empty_plaintext(self):
    """Test GCM with empty plaintext."""
    key = b"0123456789abcdef"
    iv = b"unique_iv_1234"
    plaintext = b""

    ciphertext, tag = gcm_encrypt(key, iv, plaintext)
    decrypted = gcm_decrypt(key, iv, ciphertext, tag)

    assert decrypted == plaintext
    assert ciphertext == b""

  def test_gcm_large_data(self):
    """Test GCM with large data."""
    key = b"0123456789abcdef"
    iv = b"unique_iv_1234"
    plaintext = b"X" * 10000

    ciphertext, tag = gcm_encrypt(key, iv, plaintext)
    decrypted = gcm_decrypt(key, iv, ciphertext, tag)

    assert decrypted == plaintext
    assert len(ciphertext) == len(plaintext)

  def test_gcm_different_ivs(self):
    """Test that different IVs produce different ciphertexts."""
    key = b"0123456789abcdef"
    plaintext = b"Same message"
    iv1 = b"unique_iv_0001"
    iv2 = b"unique_iv_0002"

    ciphertext1, tag1 = gcm_encrypt(key, iv1, plaintext)
    ciphertext2, tag2 = gcm_encrypt(key, iv2, plaintext)

    assert ciphertext1 != ciphertext2

  def test_gcm_deterministic(self):
    """Test that GCM is deterministic with same key and IV."""
    key = b"0123456789abcdef"
    iv = b"unique_iv_1234"
    plaintext = b"Test message"

    ciphertext1, tag1 = gcm_encrypt(key, iv, plaintext)
    ciphertext2, tag2 = gcm_encrypt(key, iv, plaintext)

    assert ciphertext1 == ciphertext2
    assert tag1 == tag2

  def test_gcm_different_keys(self):
    """Test that different keys produce different ciphertexts."""
    key1 = b"0123456789abcdef"
    key2 = b"fedcba9876543210"
    iv = b"unique_iv_1234"
    plaintext = b"Test message"

    ciphertext1, _ = gcm_encrypt(key1, iv, plaintext)
    ciphertext2, _ = gcm_encrypt(key2, iv, plaintext)

    assert ciphertext1 != ciphertext2


class TestCCM:
  """Test cases for CCM mode."""

  def test_ccm_basic_encrypt_decrypt(self):
    """Test basic CCM encryption and decryption."""
    key = b"0123456789abcdef"  # 16 bytes
    nonce = b"unique_nonce_12"  # 13 bytes
    plaintext = b"Hello, CCM!"

    ciphertext, tag = ccm_encrypt(key, nonce, plaintext)
    decrypted = ccm_decrypt(key, nonce, ciphertext, tag)

    assert decrypted == plaintext
    assert len(tag) == 16  # Default tag length

  def test_ccm_with_aad(self):
    """Test CCM with Additional Authenticated Data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_12"
    plaintext = b"Secret message"
    aad = b"authenticated header"

    ciphertext, tag = ccm_encrypt(key, nonce, plaintext, aad=aad)
    decrypted = ccm_decrypt(key, nonce, ciphertext, tag, aad=aad)

    assert decrypted == plaintext

  def test_ccm_wrong_aad_fails(self):
    """Test that decryption fails with wrong AAD."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_12"
    plaintext = b"Secret message"
    aad = b"correct_aad"

    ciphertext, tag = ccm_encrypt(key, nonce, plaintext, aad=aad)
    # Try to decrypt with wrong AAD
    decrypted = ccm_decrypt(key, nonce, ciphertext, tag, aad=b"wrong_aad")

    assert decrypted is None

  def test_ccm_tampered_ciphertext_fails(self):
    """Test that tampered ciphertext fails authentication."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_12"
    plaintext = b"Secret message"

    ciphertext, tag = ccm_encrypt(key, nonce, plaintext)

    # Tamper with ciphertext
    tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

    decrypted = ccm_decrypt(key, nonce, tampered, tag)
    assert decrypted is None

  def test_ccm_custom_mac_length(self):
    """Test CCM with custom MAC length."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_12"
    plaintext = b"Secret message"

    for mac_len in [4, 6, 8, 10, 12, 14, 16]:
      ciphertext, tag = ccm_encrypt(key, nonce, plaintext, mac_len=mac_len)
      assert len(tag) == mac_len
      decrypted = ccm_decrypt(key, nonce, ciphertext, tag)
      assert decrypted == plaintext

  def test_ccm_empty_plaintext(self):
    """Test CCM with empty plaintext."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_12"
    plaintext = b""

    ciphertext, tag = ccm_encrypt(key, nonce, plaintext)
    decrypted = ccm_decrypt(key, nonce, ciphertext, tag)

    assert decrypted == plaintext
    assert ciphertext == b""

  def test_ccm_large_data(self):
    """Test CCM with large data."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_12"
    plaintext = b"X" * 10000

    ciphertext, tag = ccm_encrypt(key, nonce, plaintext)
    decrypted = ccm_decrypt(key, nonce, ciphertext, tag)

    assert decrypted == plaintext
    assert len(ciphertext) == len(plaintext)

  def test_ccm_different_nonces(self):
    """Test that different nonces produce different ciphertexts."""
    key = b"0123456789abcdef"
    plaintext = b"Same message"
    nonce1 = b"unique_nonce_01"
    nonce2 = b"unique_nonce_02"

    ciphertext1, tag1 = ccm_encrypt(key, nonce1, plaintext)
    ciphertext2, tag2 = ccm_encrypt(key, nonce2, plaintext)

    assert ciphertext1 != ciphertext2

  def test_ccm_deterministic(self):
    """Test that CCM is deterministic with same key and nonce."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_12"
    plaintext = b"Test message"

    ciphertext1, tag1 = ccm_encrypt(key, nonce, plaintext)
    ciphertext2, tag2 = ccm_encrypt(key, nonce, plaintext)

    assert ciphertext1 == ciphertext2
    assert tag1 == tag2


class TestUtilityFunctions:
  """Test utility functions used by GCM and CCM."""

  def test_xor_bytes(self):
    """Test byte XOR function."""
    a = b"\x00\xff\x55\xaa"
    b = b"\xff\x00\xaa\x55"
    expected = b"\xff\xff\xff\xff"

    result = _xor_bytes(a, b)
    assert result == expected

  def test_xor_bytes_different_lengths(self):
    """Test byte XOR with different length inputs."""
    a = b"\xff\xff"
    b = b"\x00\x00\x00\x00"
    expected = b"\xff\xff"  # Should be truncated to shorter length

    result = _xor_bytes(a, b)
    assert result == expected

  def test_xor_bytes_empty(self):
    """Test byte XOR with empty input."""
    result = _xor_bytes(b"", b"")
    assert result == b""

  def test_generate_keystream_length(self):
    """Test keystream generation with various lengths."""
    key = b"testkey123456789"
    iv = b"testiv1234"

    for length in [0, 1, 16, 32, 64, 100, 1000]:
      keystream = _generate_keystream(key, iv, length)
      assert len(keystream) == length

  def test_generate_keystream_deterministic(self):
    """Test that keystream generation is deterministic."""
    key = b"testkey123456789"
    iv = b"testiv1234"
    length = 32

    keystream1 = _generate_keystream(key, iv, length)
    keystream2 = _generate_keystream(key, iv, length)

    assert keystream1 == keystream2

  def test_generate_keystream_different_iv(self):
    """Test that different IVs produce different keystreams."""
    key = b"testkey123456789"
    iv1 = b"testiv1111"
    iv2 = b"testiv2222"
    length = 32

    keystream1 = _generate_keystream(key, iv1, length)
    keystream2 = _generate_keystream(key, iv2, length)

    assert keystream1 != keystream2


class TestAEADEdgeCases:
  """Test edge cases for AEAD modes."""

  def test_gcm_empty_aad(self):
    """Test GCM with empty AAD."""
    key = b"0123456789abcdef"
    iv = b"unique_iv_1234"
    plaintext = b"Message"

    ciphertext1, tag1 = gcm_encrypt(key, iv, plaintext, aad=b"")
    ciphertext2, tag2 = gcm_encrypt(key, iv, plaintext)

    # Both should work
    assert gcm_decrypt(key, iv, ciphertext1, tag1, aad=b"") == plaintext
    assert gcm_decrypt(key, iv, ciphertext2, tag2) == plaintext

  def test_ccm_empty_aad(self):
    """Test CCM with empty AAD."""
    key = b"0123456789abcdef"
    nonce = b"unique_nonce_12"
    plaintext = b"Message"

    ciphertext1, tag1 = ccm_encrypt(key, nonce, plaintext, aad=b"")
    ciphertext2, tag2 = ccm_encrypt(key, nonce, plaintext)

    # Both should work
    assert ccm_decrypt(key, nonce, ciphertext1, tag1, aad=b"") == plaintext
    assert ccm_decrypt(key, nonce, ciphertext2, tag2) == plaintext

  def test_gcm_binary_data(self):
    """Test GCM with binary data."""
    key = bytes(range(16))
    iv = bytes(range(14))
    plaintext = bytes(range(256))

    ciphertext, tag = gcm_encrypt(key, iv, plaintext)
    decrypted = gcm_decrypt(key, iv, ciphertext, tag)

    assert decrypted == plaintext

  def test_ccm_binary_data(self):
    """Test CCM with binary data."""
    key = bytes(range(16))
    nonce = bytes(range(13))
    plaintext = bytes(range(256))

    ciphertext, tag = ccm_encrypt(key, nonce, plaintext)
    decrypted = ccm_decrypt(key, nonce, ciphertext, tag)

    assert decrypted == plaintext
