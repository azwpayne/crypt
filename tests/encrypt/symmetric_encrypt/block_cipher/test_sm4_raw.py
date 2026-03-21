"""Tests for SM4 block cipher raw implementation (sm4.py)."""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.block_cipher.sm4 import (
  sm4_decrypt,
  sm4_encrypt,
)

KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
PLAINTEXT = bytes.fromhex("0123456789abcdeffedcba9876543210")
# Known ciphertext from GM/T 0002-2012 standard
CIPHERTEXT = bytes.fromhex("681edf34d206965e86b3e94f536e4246")


class TestSM4Raw:
  """Tests for raw SM4 block encrypt/decrypt functions."""

  def test_encrypt_known_vector(self):
    ct = sm4_encrypt(PLAINTEXT, KEY)
    assert ct == CIPHERTEXT

  def test_decrypt_known_vector(self):
    pt = sm4_decrypt(CIPHERTEXT, KEY)
    assert pt == PLAINTEXT

  def test_encrypt_decrypt_roundtrip(self):
    ct = sm4_encrypt(PLAINTEXT, KEY)
    pt = sm4_decrypt(ct, KEY)
    assert pt == PLAINTEXT

  def test_output_is_16_bytes(self):
    ct = sm4_encrypt(PLAINTEXT, KEY)
    assert len(ct) == 16

  def test_zero_block_roundtrip(self):
    zero = b"\x00" * 16
    key = b"\x00" * 16
    ct = sm4_encrypt(zero, key)
    pt = sm4_decrypt(ct, key)
    assert pt == zero

  def test_all_ones_roundtrip(self):
    block = b"\xff" * 16
    key = b"\xff" * 16
    ct = sm4_encrypt(block, key)
    pt = sm4_decrypt(ct, key)
    assert pt == block

  def test_encrypt_changes_data(self):
    ct = sm4_encrypt(PLAINTEXT, KEY)
    assert ct != PLAINTEXT

  def test_different_keys_different_ciphertexts(self):
    key2 = b"\xff" * 16
    ct1 = sm4_encrypt(PLAINTEXT, KEY)
    ct2 = sm4_encrypt(PLAINTEXT, key2)
    assert ct1 != ct2

  def test_different_plaintexts_different_ciphertexts(self):
    pt2 = b"\xaa" * 16
    ct1 = sm4_encrypt(PLAINTEXT, KEY)
    ct2 = sm4_encrypt(pt2, KEY)
    assert ct1 != ct2
