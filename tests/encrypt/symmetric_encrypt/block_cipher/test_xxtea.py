"""Tests for XXTEA block cipher."""

from crypt.encrypt.symmetric_encrypt.block_cipher.xxtea import decrypt, encrypt

KEY = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"


class TestXXTEA:
  def test_roundtrip_short(self):
    data = b"Hello!!!"
    assert decrypt(encrypt(data, KEY), KEY) == data

  def test_roundtrip_long(self):
    data = b"A" * 64
    assert decrypt(encrypt(data, KEY), KEY) == data

  def test_roundtrip_unaligned(self):
    data = b"Hello, XXTEA!"
    assert decrypt(encrypt(data, KEY), KEY) == data

  def test_encrypt_changes_data(self):
    data = b"Test data 1234"
    assert encrypt(data, KEY) != data

  def test_different_keys_differ(self):
    data = b"Same plaintext!!"
    key2 = b"\xff" * 16
    assert encrypt(data, KEY) != encrypt(data, key2)

  def test_roundtrip_binary(self):
    data = bytes(range(32))
    assert decrypt(encrypt(data, KEY), KEY) == data
