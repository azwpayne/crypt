"""Tests for Trivium stream cipher."""

from crypt.encrypt.symmetric_encrypt.stream_cipher.trivium import (
  Trivium,
  trivium_decrypt,
  trivium_encrypt,
)

KEY = b"\x00" * 10
IV = b"\x00" * 10


class TestTrivium:
  def test_keystream_length(self):
    t = Trivium(KEY, IV)
    ks = t.keystream(32)
    assert len(ks) == 32

  def test_encrypt_decrypt_roundtrip(self):
    plaintext = b"Hello, Trivium!"
    ct = trivium_encrypt(KEY, IV, plaintext)
    assert trivium_decrypt(KEY, IV, ct) == plaintext

  def test_different_iv_gives_different_keystream(self):
    iv2 = b"\x01" + b"\x00" * 9
    ks1 = Trivium(KEY, IV).keystream(16)
    ks2 = Trivium(KEY, iv2).keystream(16)
    assert ks1 != ks2

  def test_different_key_gives_different_keystream(self):
    key2 = b"\x01" + b"\x00" * 9
    ks1 = Trivium(KEY, IV).keystream(16)
    ks2 = Trivium(key2, IV).keystream(16)
    assert ks1 != ks2

  def test_encrypt_changes_data(self):
    data = b"plaintext data!!"
    ct = trivium_encrypt(KEY, IV, data)
    assert ct != data

  def test_keystream_not_all_zero(self):
    ks = Trivium(KEY, IV).keystream(16)
    assert any(b != 0 for b in ks)
