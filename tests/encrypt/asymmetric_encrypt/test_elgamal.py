"""Tests for ElGamal asymmetric encryption."""

from crypt.encrypt.asymmetric_encrypt.elgamal import (
  decrypt,
  decrypt_bytes,
  encrypt,
  encrypt_bytes,
  generate_keypair,
)

import pytest


class TestElGamal:
  def setup_method(self):
    self.pub, self.priv = generate_keypair()

  def test_keypair_structure(self):
    p, g, h = self.pub
    assert p > 0
    assert g > 0
    assert h > 0

  def test_encrypt_decrypt_integer(self):
    m = 42
    ct = encrypt(self.pub, m)
    assert decrypt(self.pub, self.priv, ct) == m

  def test_encrypt_produces_tuple(self):
    ct = encrypt(self.pub, 100)
    assert isinstance(ct, tuple)
    assert len(ct) == 2

  def test_encrypt_is_probabilistic(self):
    # Same plaintext should produce different ciphertexts
    ct1 = encrypt(self.pub, 99)
    ct2 = encrypt(self.pub, 99)
    assert ct1 != ct2  # negligible probability of collision

  def test_encrypt_bytes_roundtrip(self):
    data = b"Hello!"
    ct = encrypt_bytes(self.pub, data)
    assert decrypt_bytes(self.pub, self.priv, ct) == data

  def test_invalid_plaintext_raises(self):
    # p, g, h = self.pub
    p, g, h = self.pub
    with pytest.raises(ValueError, match=r".*"):
      encrypt(self.pub, 0)
