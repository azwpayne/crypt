"""Comprehensive tests for all symmetric encryption algorithms.

Tests for block ciphers (AES, DES, 3DES, Blowfish, etc.) and stream ciphers.
"""

from __future__ import annotations

import pytest
from Crypto.Cipher import AES as CRYPTO_AES
from Crypto.Util.Padding import pad


class TestAESComprehensive:
  """Comprehensive tests for AES encryption."""

  @pytest.fixture
  def aes_keys(self):
    """Provide AES keys for testing."""
    return {
      128: b"\x00" * 16,
      192: b"\x00" * 24,
      256: b"\x00" * 32,
    }

  @pytest.fixture
  def test_data(self):
    """Provide test data of various sizes."""
    return [
      b"",  # Empty
      b"A",  # Single byte
      b"Hello",  # Short
      b"A" * 16,  # Exactly one block
      b"A" * 17,  # Just over one block
      b"A" * 32,  # Two blocks
      b"A" * 100,  # Multiple blocks
      bytes(range(256)),  # All bytes
    ]

  def test_aes_ecb_roundtrip(self, aes_keys, test_data):
    """Test AES ECB encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
      aes_ecb_decrypt,
      aes_ecb_encrypt,
    )

    for key_size, key in aes_keys.items():
      for data in test_data:
        encrypted = aes_ecb_encrypt(data, key)
        decrypted = aes_ecb_decrypt(encrypted, key)
        assert decrypted == data, f"AES-{key_size} ECB roundtrip failed"

  def test_aes_cbc_roundtrip(self, aes_keys, test_data):
    """Test AES CBC encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
      aes_cbc_decrypt,
      aes_cbc_encrypt,
    )

    iv = b"\x00" * 16
    for key_size, key in aes_keys.items():
      for data in test_data:
        encrypted = aes_cbc_encrypt(data, key, iv)
        decrypted = aes_cbc_decrypt(encrypted, key, iv)
        assert decrypted == data, f"AES-{key_size} CBC roundtrip failed"

  def test_aes_ctr_roundtrip(self, aes_keys, test_data):
    """Test AES CTR encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.aes import aes_ctr_crypt

    nonce = b"\x00" * 16
    for key_size, key in aes_keys.items():
      for data in test_data:
        encrypted = aes_ctr_crypt(data, key, nonce)
        decrypted = aes_ctr_crypt(encrypted, key, nonce)
        assert decrypted == data, f"AES-{key_size} CTR roundtrip failed"

  def test_aes_vs_pycryptodome(self, aes_keys):
    """Test AES against PyCryptodome reference."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
      aes_cbc_encrypt,
    )

    iv = b"\x00" * 16
    data = b"Hello, World! This is a test message."

    for key_size, key in aes_keys.items():
      # Our implementation
      our_result = aes_cbc_encrypt(data, key, iv)

      # PyCryptodome reference
      cipher = CRYPTO_AES.new(key, CRYPTO_AES.MODE_CBC, iv)
      ref_result = cipher.encrypt(pad(data, 16))

      assert our_result == ref_result, f"AES-{key_size} mismatch with PyCryptodome"


class TestDESComprehensive:
  """Comprehensive tests for DES encryption."""

  @pytest.fixture
  def des_key(self):
    """Provide DES key for testing."""
    return b"\x00" * 8

  @pytest.fixture
  def test_data(self):
    """Provide test data."""
    return [
      b"",
      b"A",
      b"Hello",
      b"A" * 8,  # One block
      b"A" * 16,  # Two blocks
      b"A" * 100,
    ]

  def test_des_roundtrip(self, des_key, test_data):
    """Test DES encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.des import (
      des_decrypt,
      des_encrypt,
    )

    iv = b"\x00" * 8
    for data in test_data:
      encrypted = des_encrypt(data, des_key, iv)
      decrypted = des_decrypt(encrypted, des_key, iv)
      assert decrypted == data, f"DES roundtrip failed for data: {data!r}"


class TestDES3Comprehensive:
  """Comprehensive tests for Triple DES encryption."""

  @pytest.fixture
  def des3_key(self):
    """Provide 3DES key for testing."""
    return b"\x00" * 24

  @pytest.fixture
  def test_data(self):
    """Provide test data."""
    return [
      b"",
      b"A",
      b"Hello",
      b"A" * 8,
      b"A" * 16,
      b"A" * 100,
    ]

  def test_des3_roundtrip(self, des3_key, test_data):
    """Test 3DES encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.des3 import (
      des3_decrypt,
      des3_encrypt,
    )

    iv = b"\x00" * 8
    for data in test_data:
      encrypted = des3_encrypt(data, des3_key, iv)
      decrypted = des3_decrypt(encrypted, des3_key, iv)
      assert decrypted == data, "3DES roundtrip failed"


class TestBlowfishComprehensive:
  """Comprehensive tests for Blowfish encryption."""

  @pytest.fixture
  def test_data(self):
    """Provide test data."""
    return [
      b"",
      b"A",
      b"Hello",
      b"A" * 8,
      b"A" * 16,
      b"A" * 100,
    ]

  def test_blowfish_roundtrip(self, test_data):
    """Test Blowfish encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.blowfish import (
      decrypt_cbc,
      encrypt_cbc,
    )

    key = b"testkey123456789"  # 16 bytes
    iv = b"\x00" * 8

    for data in test_data:
      encrypted = encrypt_cbc(key, iv, data)
      decrypted = decrypt_cbc(key, iv, encrypted)
      assert decrypted == data, "Blowfish roundtrip failed"


class TestStreamCiphers:
  """Comprehensive tests for stream ciphers."""

  @pytest.fixture
  def test_data(self):
    """Provide test data."""
    return [
      b"",
      b"A",
      b"Hello, World!",
      b"A" * 100,
      bytes(range(256)),
    ]

  def test_rc4_roundtrip(self, test_data):
    """Test RC4 encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.stream_cipher.rc4 import rc4_encrypt_decrypt

    key = b"testkey"
    for data in test_data:
      encrypted = rc4_encrypt_decrypt(data, key)
      decrypted = rc4_encrypt_decrypt(encrypted, key)
      assert decrypted == data, "RC4 roundtrip failed"

  def test_chacha20_roundtrip(self, test_data):
    """Test ChaCha20 encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.stream_cipher.chacha20 import (
      chacha20_decrypt,
      chacha20_encrypt,
    )

    key = b"\x00" * 32
    nonce = b"\x00" * 12
    counter = 0

    for data in test_data:
      encrypted = chacha20_encrypt(key, nonce, counter, data)
      decrypted = chacha20_decrypt(key, nonce, counter, encrypted)
      assert decrypted == data, "ChaCha20 roundtrip failed"

  def test_salsa20_roundtrip(self, test_data):
    """Test Salsa20 encryption/decryption roundtrip."""
    from crypt.encrypt.symmetric_encrypt.stream_cipher.salsa20 import (
      salsa20_decrypt,
      salsa20_encrypt,
    )

    key = b"\x00" * 32
    nonce = b"\x00" * 8
    counter = 0

    for data in test_data:
      encrypted = salsa20_encrypt(key, nonce, counter, data)
      decrypted = salsa20_decrypt(key, nonce, counter, encrypted)
      assert decrypted == data, "Salsa20 roundtrip failed"


class TestClassicCiphers:
  """Tests for classic/educational ciphers."""

  def test_caesar_cipher(self):
    """Test Caesar cipher encryption/decryption."""
    from crypt.encrypt.symmetric_encrypt.stream_cipher.caesar import (
      caesar_decrypt,
      caesar_encrypt,
    )

    plaintext = "HELLOWORLD"
    for shift in range(26):
      encrypted = caesar_encrypt(plaintext, shift)
      decrypted = caesar_decrypt(encrypted, shift)
      assert decrypted == plaintext, f"Caesar cipher failed with shift {shift}"

  def test_rot13(self):
    """Test ROT13 encryption/decryption."""
    from crypt.encrypt.symmetric_encrypt.stream_cipher.rot13 import rot13

    plaintext = "HELLOWORLD"
    encrypted = rot13(plaintext)
    decrypted = rot13(encrypted)
    assert decrypted == plaintext, "ROT13 roundtrip failed"

  def test_vigenere_cipher(self):
    """Test Vigenere cipher encryption/decryption."""
    from crypt.encrypt.symmetric_encrypt.stream_cipher.vigenere_cipher import (
      vigenere_decrypt,
      vigenere_encrypt,
    )

    plaintext = "HELLOWORLD"
    key = "KEY"
    encrypted = vigenere_encrypt(plaintext, key)
    decrypted = vigenere_decrypt(encrypted, key)
    assert decrypted == plaintext, "Vigenere cipher roundtrip failed"

  def test_atbash_cipher(self):
    """Test Atbash cipher encryption/decryption."""
    from crypt.encrypt.symmetric_encrypt.stream_cipher.atbash_cipher import (
      atbash_decrypt,
      atbash_encrypt,
    )

    plaintext = "HELLOWORLD"
    encrypted = atbash_encrypt(plaintext)
    decrypted = atbash_decrypt(encrypted)
    assert decrypted == plaintext, "Atbash cipher roundtrip failed"


class TestEncryptionEdgeCases:
  """Edge case tests for encryption algorithms."""

  def test_empty_plaintext(self):
    """Test encryption with empty plaintext."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
      aes_ecb_decrypt,
      aes_ecb_encrypt,
    )

    key = b"\x00" * 16
    self._extracted_from_test_binary_data_9(aes_ecb_encrypt, b"", key, aes_ecb_decrypt)

  def test_large_data(self):
    """Test encryption with large data."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
      aes_ecb_decrypt,
      aes_ecb_encrypt,
    )

    key = b"\x00" * 16
    data = b"x" * 10000

    self._extracted_from_test_binary_data_9(aes_ecb_encrypt, data, key, aes_ecb_decrypt)

  def test_binary_data(self):
    """Test encryption with all byte values."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
      aes_ecb_decrypt,
      aes_ecb_encrypt,
    )

    key = b"\x00" * 16
    data = bytes(range(256))

    self._extracted_from_test_binary_data_9(aes_ecb_encrypt, data, key, aes_ecb_decrypt)

  def _extracted_from_test_binary_data_9(
    self, aes_ecb_encrypt, arg1, key, aes_ecb_decrypt
  ):
    encrypted = aes_ecb_encrypt(arg1, key)
    decrypted = aes_ecb_decrypt(encrypted, key)
    assert decrypted == arg1

  def test_deterministic(self):
    """Test that encryption is deterministic with same key/IV."""
    from crypt.encrypt.symmetric_encrypt.block_cipher.aes import aes_ecb_encrypt

    key = b"\x00" * 16
    data = b"test data"

    results = [aes_ecb_encrypt(data, key) for _ in range(10)]
    assert all(r == results[0] for r in results)
