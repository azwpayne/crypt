"""Tests for CAST5 (CAST-128) block cipher implementation."""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.block_cipher.cast5 import (
  CAST5,
  _pkcs7_unpad,
  cast5_cbc_decrypt,
  cast5_cbc_encrypt,
  cast5_ecb_decrypt,
  cast5_ecb_encrypt,
  decrypt_block,
  encrypt_block,
  key_schedule,
)

import pytest

KEY_128 = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
BLOCK = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
IV = b"\x00" * 8


class TestCAST5Block:
  """Tests for CAST5 block-level operations."""

  def test_encrypt_output_length(self):
    ct = encrypt_block(BLOCK, KEY_128)
    assert len(ct) == 8

  def test_encrypt_decrypt_roundtrip_128bit_key(self):
    ct = encrypt_block(BLOCK, KEY_128)
    pt = decrypt_block(ct, KEY_128)
    assert pt == BLOCK

  def test_encrypt_decrypt_roundtrip_80bit_key(self):
    key = b"\x01" * 10  # 80-bit key (12 rounds)
    ct = encrypt_block(BLOCK, key)
    pt = decrypt_block(ct, key)
    assert pt == BLOCK

  def test_encrypt_changes_data(self):
    ct = encrypt_block(BLOCK, KEY_128)
    assert ct != BLOCK

  def test_zero_block_roundtrip(self):
    zero = b"\x00" * 8
    ct = encrypt_block(zero, KEY_128)
    pt = decrypt_block(ct, KEY_128)
    assert pt == zero

  def test_all_ones_block_roundtrip(self):
    block = b"\xff" * 8
    ct = encrypt_block(block, KEY_128)
    pt = decrypt_block(ct, KEY_128)
    assert pt == block

  def test_different_keys_different_ciphertexts(self):
    key2 = b"\xff" * 16
    ct1 = encrypt_block(BLOCK, KEY_128)
    ct2 = encrypt_block(BLOCK, key2)
    assert ct1 != ct2


class TestCAST5ECB:
  """Tests for CAST5 ECB mode."""

  def test_ecb_roundtrip_single_block(self):
    data = b"ABCDEFGH"  # 8 bytes = 1 block
    ct = cast5_ecb_encrypt(data, KEY_128)
    pt = cast5_ecb_decrypt(ct, KEY_128)
    assert pt == data

  def test_ecb_roundtrip_two_blocks(self):
    data = b"A" * 16
    ct = cast5_ecb_encrypt(data, KEY_128)
    pt = cast5_ecb_decrypt(ct, KEY_128)
    assert pt == data

  def test_ecb_roundtrip_short_data(self):
    data = b"Hi"
    ct = cast5_ecb_encrypt(data, KEY_128)
    pt = cast5_ecb_decrypt(ct, KEY_128)
    assert pt == data

  def test_ecb_roundtrip_three_blocks(self):
    data = b"B" * 24
    ct = cast5_ecb_encrypt(data, KEY_128)
    pt = cast5_ecb_decrypt(ct, KEY_128)
    assert pt == data


class TestCAST5CBC:
  """Tests for CAST5 CBC mode."""

  def test_cbc_roundtrip(self):
    data = b"Hello, CAST5!!!!"  # 16 bytes
    ct = cast5_cbc_encrypt(data, KEY_128, IV)
    pt = cast5_cbc_decrypt(ct, KEY_128, IV)
    assert pt == data

  def test_cbc_roundtrip_multiple_blocks(self):
    data = b"C" * 32
    ct = cast5_cbc_encrypt(data, KEY_128, IV)
    pt = cast5_cbc_decrypt(ct, KEY_128, IV)
    assert pt == data

  def test_cbc_differs_from_ecb(self):
    data = b"D" * 16
    ct_ecb = cast5_ecb_encrypt(data, KEY_128)
    ct_cbc = cast5_cbc_encrypt(data, KEY_128, IV)
    assert ct_ecb != ct_cbc

  def test_cbc_wrong_iv_corrupts_first_block(self):
    data = b"E" * 16
    ct = cast5_cbc_encrypt(data, KEY_128, IV)
    wrong_iv = b"\xff" * 8
    pt = cast5_cbc_decrypt(ct, KEY_128, wrong_iv)
    assert pt != data

  def test_cbc_short_data(self):
    data = b"short"
    ct = cast5_cbc_encrypt(data, KEY_128, IV)
    pt = cast5_cbc_decrypt(ct, KEY_128, IV)
    assert pt == data


class TestCAST5ErrorPaths:
  """Tests for CAST5 error paths."""

  def test_invalid_key_length_too_short(self):
    with pytest.raises(ValueError, match="Key must be 5-16 bytes"):
      CAST5(b"\x00" * 4)

  def test_invalid_key_length_too_long(self):
    with pytest.raises(ValueError, match="Key must be 5-16 bytes"):
      CAST5(b"\x00" * 17)

  def test_key_schedule_invalid_key(self):
    with pytest.raises(ValueError, match="Key must be 5-16 bytes"):
      key_schedule(b"\x00" * 4)

  def test_encrypt_block_invalid_size(self):
    cipher = CAST5(KEY_128)
    with pytest.raises(ValueError, match="Block must be 8 bytes"):
      cipher.encrypt_block(b"\x00" * 7)

  def test_decrypt_block_invalid_size(self):
    cipher = CAST5(KEY_128)
    with pytest.raises(ValueError, match="Block must be 8 bytes"):
      cipher.decrypt_block(b"\x00" * 9)

  def test_ecb_decrypt_invalid_ciphertext_length(self):
    with pytest.raises(ValueError, match="Ciphertext length must be a multiple of 8"):
      cast5_ecb_decrypt(b"\x00" * 7, KEY_128)

  def test_cbc_encrypt_invalid_iv_length(self):
    with pytest.raises(ValueError, match="IV must be 8 bytes"):
      cast5_cbc_encrypt(b"test", KEY_128, b"\x00" * 7)

  def test_cbc_decrypt_invalid_ciphertext_length(self):
    with pytest.raises(ValueError, match="Ciphertext length must be a multiple of 8"):
      cast5_cbc_decrypt(b"\x00" * 7, KEY_128, IV)

  def test_cbc_decrypt_invalid_iv_length(self):
    with pytest.raises(ValueError, match="IV must be 8 bytes"):
      cast5_cbc_decrypt(b"\x00" * 8, KEY_128, b"\x00" * 7)

  def test_pkcs7_unpad_empty_data(self):
    with pytest.raises(ValueError, match="Empty data"):
      _pkcs7_unpad(b"")

  def test_pkcs7_unpad_invalid_padding_length(self):
    with pytest.raises(ValueError, match="Invalid padding length"):
      _pkcs7_unpad(b"\x00" * 8 + b"\x09")

  def test_pkcs7_unpad_data_too_short(self):
    with pytest.raises(ValueError, match="Data too short for padding"):
      _pkcs7_unpad(b"\x08\x08")

  def test_pkcs7_unpad_invalid_padding_bytes(self):
    with pytest.raises(ValueError, match="Invalid padding bytes"):
      _pkcs7_unpad(b"\x00" * 7 + b"\x02")
