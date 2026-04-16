"""Tests for XTEA block cipher."""

from crypt.encrypt.symmetric_encrypt.block_cipher.xtea import (
  _parse_key,
  decrypt_block,
  encrypt_block,
  xtea_cbc_decrypt,
  xtea_cbc_encrypt,
  xtea_ecb_decrypt,
  xtea_ecb_encrypt,
)

import pytest

KEY = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
BLOCK = b"\x41\x42\x43\x44\x45\x46\x47\x48"  # 8 bytes
IV = b"\x00" * 8


class TestXTEABlock:
  def test_encrypt_output_length(self):
    assert len(encrypt_block(BLOCK, KEY)) == 8

  def test_roundtrip(self):
    ct = encrypt_block(BLOCK, KEY)
    assert decrypt_block(ct, KEY) == BLOCK

  def test_encrypt_changes_data(self):
    assert encrypt_block(BLOCK, KEY) != BLOCK

  def test_different_keys_differ(self):
    key2 = b"\xff" * 16
    assert encrypt_block(BLOCK, KEY) != encrypt_block(BLOCK, key2)


class TestXTEAECB:
  def test_ecb_roundtrip(self):
    data = b"ABCDEFGH12345678"
    assert xtea_ecb_decrypt(xtea_ecb_encrypt(data, KEY), KEY) == data

  def test_ecb_unaligned(self):
    data = b"Hello!"
    assert xtea_ecb_decrypt(xtea_ecb_encrypt(data, KEY), KEY) == data

  def test_ecb_multiple_blocks(self):
    data = b"X" * 32
    assert xtea_ecb_decrypt(xtea_ecb_encrypt(data, KEY), KEY) == data


class TestXTEACBC:
  def test_cbc_roundtrip(self):
    data = b"CBC mode test!12"
    assert xtea_cbc_decrypt(xtea_cbc_encrypt(data, KEY, IV), KEY, IV) == data

  def test_cbc_multiple_blocks(self):
    data = b"B" * 32
    assert xtea_cbc_decrypt(xtea_cbc_encrypt(data, KEY, IV), KEY, IV) == data

  def test_cbc_differs_from_ecb(self):
    data = b"A" * 16
    assert xtea_ecb_encrypt(data, KEY) != xtea_cbc_encrypt(data, KEY, IV)

  def test_cbc_wrong_iv_corrupts(self):
    data = b"D" * 16
    ct = xtea_cbc_encrypt(data, KEY, IV)
    wrong_iv = b"\xff" * 8
    assert xtea_cbc_decrypt(ct, KEY, wrong_iv) != data


class TestXTEAErrorPaths:
  """Tests for XTEA error paths."""

  def test_parse_key_invalid_length(self):
    with pytest.raises(ValueError, match="Key must be 16 bytes"):
      _parse_key(b"\x00" * 15)

  def test_encrypt_block_invalid_size(self):
    with pytest.raises(ValueError, match="Block must be 8 bytes"):
      encrypt_block(b"\x00" * 7, KEY)

  def test_decrypt_block_invalid_size(self):
    with pytest.raises(ValueError, match="Block must be 8 bytes"):
      decrypt_block(b"\x00" * 9, KEY)

  def test_ecb_decrypt_invalid_ciphertext_length(self):
    with pytest.raises(ValueError, match="Ciphertext length must be a multiple of block size"):
      xtea_ecb_decrypt(b"\x00" * 7, KEY)

  def test_cbc_encrypt_invalid_iv_length(self):
    with pytest.raises(ValueError, match="IV must be 8 bytes"):
      xtea_cbc_encrypt(b"test", KEY, b"\x00" * 7)

  def test_cbc_decrypt_invalid_iv_length(self):
    with pytest.raises(ValueError, match="IV must be 8 bytes"):
      xtea_cbc_decrypt(b"\x00" * 8, KEY, b"\x00" * 7)

  def test_cbc_decrypt_invalid_ciphertext_length(self):
    with pytest.raises(ValueError, match="Ciphertext length must be a multiple of block size"):
      xtea_cbc_decrypt(b"\x00" * 7, KEY, IV)
