"""Tests for SIMON and BELT block cipher implementations."""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.block_cipher.belt import belt_decrypt, belt_encrypt
from crypt.encrypt.symmetric_encrypt.block_cipher.simon import (
  simon_decrypt,
  simon_encrypt,
)

import pytest


class TestSimon:
  """Tests for SIMON lightweight block cipher."""

  def test_simon64_encrypt_decrypt_roundtrip(self):
    block = bytes(range(8))
    key = bytes(range(16))
    ct = simon_encrypt(block, key, block_size=64)
    pt = simon_decrypt(ct, key, block_size=64)
    assert pt == block

  def test_simon128_encrypt_decrypt_roundtrip(self):
    block = bytes(range(16))
    key = bytes(range(32))
    ct = simon_encrypt(block, key, block_size=128)
    pt = simon_decrypt(ct, key, block_size=128)
    assert pt == block

  def test_simon64_output_length(self):
    block = b"\x00" * 8
    key = b"\x00" * 16
    assert len(simon_encrypt(block, key, block_size=64)) == 8

  def test_simon128_output_length(self):
    block = b"\x00" * 16
    key = b"\x00" * 32
    assert len(simon_encrypt(block, key, block_size=128)) == 16

  def test_simon_encrypt_changes_block(self):
    block = b"\x01" * 8
    key = b"\x02" * 16
    ct = simon_encrypt(block, key, block_size=64)
    # Key bytes are non-zero so ciphertext should differ from plaintext
    assert ct != block

  def test_simon64_invalid_block_size_raises(self):
    with pytest.raises(ValueError):
      simon_encrypt(b"\x00" * 7, b"\x00" * 16, block_size=64)

  def test_simon64_invalid_key_size_raises(self):
    with pytest.raises(ValueError):
      simon_encrypt(b"\x00" * 8, b"\x00" * 8, block_size=64)

  def test_simon_invalid_block_size_param_raises(self):
    with pytest.raises(ValueError):
      simon_encrypt(b"\x00" * 16, b"\x00" * 16, block_size=32)

  def test_simon_zero_key_zero_block(self):
    block = b"\x00" * 8
    key = b"\x00" * 16
    ct = simon_encrypt(block, key, block_size=64)
    pt = simon_decrypt(ct, key, block_size=64)
    assert pt == block


class TestBelt:
  """Tests for BELT block cipher (Belarusian STB 34.101.31)."""

  def test_encrypt_decrypt_roundtrip(self):
    block = bytes(range(16))
    key = bytes(range(32))
    ct = belt_encrypt(block, key)
    pt = belt_decrypt(ct, key)
    assert pt == block

  def test_output_is_16_bytes(self):
    block = b"\x00" * 16
    key = b"\x00" * 32
    assert len(belt_encrypt(block, key)) == 16

  def test_xor_involution(self):
    """BELT simplified impl uses XOR so encrypt == decrypt."""
    block = b"\xab" * 16
    key = b"\xcd" * 32
    ct = belt_encrypt(block, key)
    assert belt_decrypt(ct, key) == block

  def test_invalid_block_size_raises(self):
    with pytest.raises(ValueError):
      belt_encrypt(b"\x00" * 8, b"\x00" * 32)

  def test_invalid_key_size_raises(self):
    with pytest.raises(ValueError):
      belt_encrypt(b"\x00" * 16, b"\x00" * 16)

  def test_decrypt_invalid_block_raises(self):
    with pytest.raises(ValueError):
      belt_decrypt(b"\x00" * 8, b"\x00" * 32)

  def test_decrypt_invalid_key_raises(self):
    with pytest.raises(ValueError):
      belt_decrypt(b"\x00" * 16, b"\x00" * 8)

  def test_different_plaintexts_give_different_ciphertexts(self):
    key = b"k" * 32
    ct1 = belt_encrypt(b"\x00" * 16, key)
    ct2 = belt_encrypt(b"\xff" * 16, key)
    assert ct1 != ct2
