# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_aes.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for AES block cipher implementation

from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
  _decrypt_block,
  _encrypt_block,
  add_round_key,
  aes_cbc_decrypt,
  aes_cbc_encrypt,
  aes_ctr_crypt,
  aes_decrypt,
  aes_ecb_decrypt,
  aes_ecb_encrypt,
  aes_encrypt,
  key_expansion,
  mix_columns,
  pkcs7_pad,
  pkcs7_unpad,
  shift_rows,
  sub_bytes,
)

import pytest
from Crypto.Cipher import AES as CRYPTO_AES
from Crypto.Util.Padding import pad


# Test vectors from NIST SP 800-38A
class TestAESKeyExpansion:
  """Test key expansion for different key sizes."""

  def test_key_expansion_128(self):
    """Test AES-128 key expansion."""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    expanded = key_expansion(key)
    # Should produce 11 round keys (44 words = 176 bytes)
    assert len(expanded) == 176

  def test_key_expansion_192(self):
    """Test AES-192 key expansion."""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    expanded = key_expansion(key)
    # Should produce 13 round keys (52 words = 208 bytes)
    assert len(expanded) == 208

  def test_key_expansion_256(self):
    """Test AES-256 key expansion."""
    key = bytes.fromhex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    expanded = key_expansion(key)
    # Should produce 15 round keys (60 words = 240 bytes)
    assert len(expanded) == 240

  def test_key_expansion_invalid_length(self):
    """Test key expansion with invalid key length."""
    with pytest.raises(ValueError, match="Invalid key length"):
      key_expansion(b"short_key")


class TestAESBasicOperations:
  """Test basic AES operations."""

  def test_sub_bytes(self):
    """Test SubBytes transformation."""
    state = bytearray(
      [
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
      ]
    )
    sub_bytes(state)
    # 0x00 -> 0x63, 0x01 -> 0x7c, etc.
    assert state[0] == 0x63
    assert state[1] == 0x7C

  def test_sub_bytes_inverse(self):
    """Test inverse SubBytes transformation."""
    original = bytearray(
      [
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
      ]
    )
    state = original.copy()
    sub_bytes(state)
    sub_bytes(state, inv=True)
    assert state == original

  def test_shift_rows(self):
    """Test ShiftRows transformation."""
    # State in column-major order
    state = bytearray(range(16))
    original = state.copy()
    shift_rows(state)
    # Row 0 should be unchanged
    assert state[0] == original[0]
    assert state[4] == original[4]
    assert state[8] == original[8]
    assert state[12] == original[12]

  def test_shift_rows_inverse(self):
    """Test inverse ShiftRows transformation."""
    original = bytearray(range(16))
    state = original.copy()
    shift_rows(state)
    shift_rows(state, inv=True)
    assert state == original

  def test_mix_columns(self):
    """Test MixColumns transformation."""
    state = bytearray(
      [
        0xDB,
        0x13,
        0x53,
        0x45,
        0xF2,
        0x0A,
        0x22,
        0x5C,
        0x01,
        0x01,
        0x01,
        0x01,
        0xC6,
        0xC6,
        0xC6,
        0xC6,
      ]
    )
    mix_columns(state)
    # Expected result for first column
    assert state[0] == 0x8E
    assert state[1] == 0x4D
    assert state[2] == 0xA1
    assert state[3] == 0xBC

  def test_mix_columns_inverse(self):
    """Test inverse MixColumns transformation."""
    original = bytearray(
      [
        0xDB,
        0x13,
        0x53,
        0x45,
        0xF2,
        0x0A,
        0x22,
        0x5C,
        0x01,
        0x01,
        0x01,
        0x01,
        0xC6,
        0xC6,
        0xC6,
        0xC6,
      ]
    )
    state = original.copy()
    mix_columns(state)
    mix_columns(state, inv=True)
    assert state == original

  def test_add_round_key(self):
    """Test AddRoundKey transformation."""
    state = bytearray(
      [
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
      ]
    )
    round_key = bytes([0xFF] * 16)
    add_round_key(state, round_key)
    expected = bytearray(
      [
        0xFF,
        0xFE,
        0xFD,
        0xFC,
        0xFB,
        0xFA,
        0xF9,
        0xF8,
        0xF7,
        0xF6,
        0xF5,
        0xF4,
        0xF3,
        0xF2,
        0xF1,
        0xF0,
      ]
    )
    assert state == expected


class TestAESECB:
  """Test AES-ECB mode."""

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_ecb_basic(self, key_size):
    """Test basic ECB encryption/decryption."""
    key = bytes(range(key_size))
    plaintext = b"Hello, World!!!!"  # 16 bytes
    ciphertext = aes_ecb_encrypt(plaintext, key)
    decrypted = aes_ecb_decrypt(ciphertext, key)
    assert decrypted == plaintext

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_ecb_multiblock(self, key_size):
    """Test ECB with multiple blocks."""
    key = bytes(range(key_size))
    plaintext = b"This is a longer message that spans multiple blocks!"
    ciphertext = aes_ecb_encrypt(plaintext, key)
    decrypted = aes_ecb_decrypt(ciphertext, key)
    assert decrypted == plaintext

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_ecb_against_pycryptodome(self, key_size):
    """Test ECB against pycryptodome reference."""
    key = bytes(range(key_size))
    plaintext = b"Test message for AES encryption!"

    # Our implementation
    our_ciphertext = aes_ecb_encrypt(plaintext, key)

    # PyCryptodome reference
    cipher = CRYPTO_AES.new(key, CRYPTO_AES.MODE_ECB)
    expected_ciphertext = cipher.encrypt(pad(plaintext, 16))

    assert our_ciphertext == expected_ciphertext

  def test_ecb_empty(self):
    """Test ECB with empty plaintext."""
    key = b"0123456789abcdef"
    plaintext = b""
    ciphertext = aes_ecb_encrypt(plaintext, key)
    decrypted = aes_ecb_decrypt(ciphertext, key)
    assert decrypted == plaintext

  def test_ecb_invalid_key(self):
    """Test ECB with invalid key length."""
    with pytest.raises(ValueError, match="Invalid key length"):
      aes_ecb_encrypt(b"test", b"short")


class TestAESCBC:
  """Test AES-CBC mode."""

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_cbc_basic(self, key_size):
    """Test basic CBC encryption/decryption."""
    key = bytes(range(key_size))
    iv = bytes(range(16, 32))
    plaintext = b"Hello, World!!!!"
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    decrypted = aes_cbc_decrypt(ciphertext, key, iv)
    assert decrypted == plaintext

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_cbc_multiblock(self, key_size):
    """Test CBC with multiple blocks."""
    key = bytes(range(key_size))
    iv = bytes(range(16, 32))
    plaintext = b"This is a longer message that spans multiple blocks!"
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    decrypted = aes_cbc_decrypt(ciphertext, key, iv)
    assert decrypted == plaintext

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_cbc_against_pycryptodome(self, key_size):
    """Test CBC against pycryptodome reference."""
    key = bytes(range(key_size))
    iv = bytes(range(16, 32))
    plaintext = b"Test message for AES encryption!"

    # Our implementation
    our_ciphertext = aes_cbc_encrypt(plaintext, key, iv)

    # PyCryptodome reference
    cipher = CRYPTO_AES.new(key, CRYPTO_AES.MODE_CBC, iv=iv)
    expected_ciphertext = cipher.encrypt(pad(plaintext, 16))

    assert our_ciphertext == expected_ciphertext

  def test_cbc_iv_chaining(self):
    """Test that CBC properly chains blocks."""
    key = b"0123456789abcdef"
    iv1 = b"1234567890123456"
    iv2 = b"6543210987654321"
    plaintext = b"Block1Block2Block3"

    # Same plaintext, different IVs should produce different ciphertexts
    ciphertext1 = aes_cbc_encrypt(plaintext, key, iv1)
    ciphertext2 = aes_cbc_encrypt(plaintext, key, iv2)
    assert ciphertext1 != ciphertext2

  def test_cbc_invalid_iv(self):
    """Test CBC with invalid IV length."""
    with pytest.raises(ValueError, match="IV must be 16 bytes"):
      aes_cbc_encrypt(b"test", b"0123456789abcdef", b"short_iv")


class TestAESCTR:
  """Test AES-CTR mode."""

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_ctr_basic(self, key_size):
    """Test basic CTR encryption/decryption."""
    key = bytes(range(key_size))
    nonce = bytes(range(16, 32))
    plaintext = b"Hello, World!!!!"
    ciphertext = aes_ctr_crypt(plaintext, key, nonce)
    decrypted = aes_ctr_crypt(ciphertext, key, nonce)
    assert decrypted == plaintext

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_ctr_multiblock(self, key_size):
    """Test CTR with multiple blocks."""
    key = bytes(range(key_size))
    nonce = bytes(range(16, 32))
    plaintext = b"This is a longer message that spans multiple blocks and more!"
    ciphertext = aes_ctr_crypt(plaintext, key, nonce)
    decrypted = aes_ctr_crypt(ciphertext, key, nonce)
    assert decrypted == plaintext

  @pytest.mark.parametrize("key_size", [16, 24, 32])
  def test_ctr_against_pycryptodome(self, key_size):
    """Test CTR against pycryptodome reference."""
    key = bytes(range(key_size))
    # PyCryptodome uses nonce + initial_value format
    nonce = bytes(range(8, 16))  # 8 bytes
    initial_value = int.from_bytes(bytes(range(16, 24)), "big")
    plaintext = b"Test message for AES encryption!"

    # Our implementation uses full 16-byte nonce
    full_nonce = nonce + initial_value.to_bytes(8, "big")
    our_ciphertext = aes_ctr_crypt(plaintext, key, full_nonce)

    # PyCryptodome reference
    cipher = CRYPTO_AES.new(
      key, CRYPTO_AES.MODE_CTR, nonce=nonce, initial_value=initial_value
    )
    expected_ciphertext = cipher.encrypt(plaintext)

    assert our_ciphertext == expected_ciphertext

  def test_ctr_symmetric(self):
    """Test that CTR encryption and decryption are the same operation."""
    key = b"0123456789abcdef"
    nonce = b"1234567890123456"
    plaintext = b"Test data for CTR"

    ciphertext = aes_ctr_crypt(plaintext, key, nonce)
    # Double encryption should return plaintext
    double_encrypted = aes_ctr_crypt(ciphertext, key, nonce)
    assert double_encrypted == plaintext

  def test_ctr_invalid_nonce(self):
    """Test CTR with invalid nonce length."""
    with pytest.raises(ValueError, match="Nonce must be 16 bytes"):
      aes_ctr_crypt(b"test", b"0123456789abcdef", b"short_nonce")


class TestAESGeneric:
  """Test generic AES encrypt/decrypt functions."""

  def test_generic_ecb(self):
    """Test generic function with ECB mode."""
    key = b"0123456789abcdef"
    plaintext = b"Hello, World!!!!"
    ciphertext = aes_encrypt(plaintext, key, mode="ecb")
    decrypted = aes_decrypt(ciphertext, key, mode="ecb")
    assert decrypted == plaintext

  def test_generic_cbc(self):
    """Test generic function with CBC mode."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    plaintext = b"Hello, World!!!!"
    ciphertext = aes_encrypt(plaintext, key, mode="cbc", iv=iv)
    decrypted = aes_decrypt(ciphertext, key, mode="cbc", iv=iv)
    assert decrypted == plaintext

  def test_generic_ctr(self):
    """Test generic function with CTR mode."""
    key = b"0123456789abcdef"
    nonce = b"1234567890123456"
    plaintext = b"Hello, World!!!!"
    ciphertext = aes_encrypt(plaintext, key, mode="ctr", iv=nonce)
    decrypted = aes_decrypt(ciphertext, key, mode="ctr", iv=nonce)
    assert decrypted == plaintext

  def test_generic_invalid_mode(self):
    """Test generic function with invalid mode."""
    with pytest.raises(ValueError, match="Unsupported mode"):
      aes_encrypt(b"test", b"0123456789abcdef", mode="invalid")  # type: ignore[arg-type]

  def test_generic_missing_iv_cbc(self):
    """Test generic function with missing IV for CBC."""
    with pytest.raises(ValueError, match="IV is required"):
      aes_encrypt(b"test", b"0123456789abcdef", mode="cbc")

  def test_generic_missing_iv_ctr(self):
    """Test generic function with missing nonce for CTR."""
    with pytest.raises(ValueError, match="Nonce is required"):
      aes_encrypt(b"test", b"0123456789abcdef", mode="ctr")


class TestPKCS7:
  """Test PKCS7 padding."""

  def test_pkcs7_pad_basic(self):
    """Test basic PKCS7 padding."""
    data = b"Hello"
    padded = pkcs7_pad(data)
    assert len(padded) == 16
    assert padded[-1] == 11  # 11 padding bytes

  def test_pkcs7_pad_full_block(self):
    """Test PKCS7 padding for full block."""
    data = b"0123456789abcdef"
    padded = pkcs7_pad(data)
    assert len(padded) == 32
    assert padded[-1] == 16  # Full block of padding

  def test_pkcs7_unpad_basic(self):
    """Test basic PKCS7 unpadding."""
    data = b"Hello"
    padded = pkcs7_pad(data)
    unpadded = pkcs7_unpad(padded)
    assert unpadded == data

  def test_pkcs7_unpad_full_block(self):
    """Test PKCS7 unpadding for full block padding."""
    data = b"0123456789abcdef"
    padded = pkcs7_pad(data)
    unpadded = pkcs7_unpad(padded)
    assert unpadded == data

  def test_pkcs7_empty(self):
    """Test PKCS7 padding for empty data."""
    data = b""
    padded = pkcs7_pad(data)
    assert len(padded) == 16
    unpadded = pkcs7_unpad(padded)
    assert unpadded == data

  def test_pkcs7_unpad_invalid_length(self):
    """Test PKCS7 unpadding with invalid padding length."""
    with pytest.raises(ValueError, match="Invalid padding length"):
      pkcs7_unpad(b"short")

  def test_pkcs7_unpad_invalid_bytes(self):
    """Test PKCS7 unpadding with invalid padding bytes."""
    # Create data with inconsistent padding
    data = b"test\x02\x03\x03"  # Should be \x03\x03\x03
    with pytest.raises(ValueError, match="Invalid padding bytes"):
      pkcs7_unpad(data)


class TestAESNISTVectors:
  """Test against NIST SP 800-38A test vectors."""

  def test_nist_ecb_example1(self):
    """Test NIST ECB example 1."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")

    # Our implementation adds padding, so we need to handle this
    expanded = key_expansion(key)
    result = _encrypt_block(plaintext, expanded, 10)
    assert result == expected

  def test_nist_ecb_decryption(self):
    """Test NIST ECB decryption."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    ciphertext = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    expected = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    expanded = key_expansion(key)
    result = _decrypt_block(ciphertext, expanded, 10)
    assert result == expected

  def test_nist_cbc_example1(self):
    """Test NIST CBC example 1."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    # Encrypt single block
    xored = bytes([plaintext[i] ^ iv[i] for i in range(16)])
    expanded = key_expansion(key)
    result = _encrypt_block(xored, expanded, 10)
    expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    assert result == expected


class TestAESEdgeCases:
  """Test edge cases and error handling."""

  def test_ecb_ciphertext_not_multiple_of_block(self):
    """Test ECB decryption with invalid ciphertext length."""
    with pytest.raises(ValueError, match="multiple of 16"):
      aes_ecb_decrypt(b"short", b"0123456789abcdef")

  def test_cbc_ciphertext_not_multiple_of_block(self):
    """Test CBC decryption with invalid ciphertext length."""
    with pytest.raises(ValueError, match="multiple of 16"):
      aes_cbc_decrypt(b"short", b"0123456789abcdef", b"1234567890123456")

  def test_large_data_ecb(self):
    """Test ECB with large data."""
    key = b"0123456789abcdef"
    plaintext = b"A" * 10000
    ciphertext = aes_ecb_encrypt(plaintext, key)
    decrypted = aes_ecb_decrypt(ciphertext, key)
    assert decrypted == plaintext

  def test_large_data_cbc(self):
    """Test CBC with large data."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    plaintext = b"B" * 10000
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    decrypted = aes_cbc_decrypt(ciphertext, key, iv)
    assert decrypted == plaintext

  def test_large_data_ctr(self):
    """Test CTR with large data."""
    key = b"0123456789abcdef"
    nonce = b"1234567890123456"
    plaintext = b"C" * 10000
    ciphertext = aes_ctr_crypt(plaintext, key, nonce)
    decrypted = aes_ctr_crypt(ciphertext, key, nonce)
    assert decrypted == plaintext

  def test_binary_data(self):
    """Test with binary data containing all byte values."""
    key = b"0123456789abcdef"
    plaintext = bytes(range(256))

    # ECB
    ciphertext = aes_ecb_encrypt(plaintext, key)
    assert aes_ecb_decrypt(ciphertext, key) == plaintext

    # CBC
    iv = b"1234567890123456"
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    assert aes_cbc_decrypt(ciphertext, key, iv) == plaintext

    # CTR
    nonce = b"1234567890123456"
    ciphertext = aes_ctr_crypt(plaintext, key, nonce)
    assert aes_ctr_crypt(ciphertext, key, nonce) == plaintext
