"""Tests for ElGamal asymmetric encryption."""

from crypt.encrypt.asymmetric_encrypt.elgamal import (
  _miller_rabin,
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
    ct1 = encrypt(self.pub, 99)
    ct2 = encrypt(self.pub, 99)
    assert ct1 != ct2

  def test_encrypt_bytes_roundtrip(self):
    data = b"Hello!"
    ct = encrypt_bytes(self.pub, data)
    assert decrypt_bytes(self.pub, self.priv, ct) == data

  def test_invalid_plaintext_raises(self):
    p, g, h = self.pub
    with pytest.raises(ValueError, match=r".*"):
      encrypt(self.pub, 0)

  def test_miller_rabin_small_primes(self):
    assert _miller_rabin(2) is True
    assert _miller_rabin(3) is True

  def test_miller_rabin_composites(self):
    assert _miller_rabin(1) is False
    assert _miller_rabin(4) is False
    assert _miller_rabin(0) is False

  def test_miller_rabin_known_primes(self):
    assert _miller_rabin(5) is True
    assert _miller_rabin(7) is True
    assert _miller_rabin(11) is True
    assert _miller_rabin(97) is True

  def test_miller_rabin_known_composites(self):
    assert _miller_rabin(9) is False
    assert _miller_rabin(15) is False
    assert _miller_rabin(100) is False

  def test_miller_rabin_edge_cases(self):
    assert _miller_rabin(2) is True
    assert _miller_rabin(3) is True
    assert _miller_rabin(0) is False
    assert _miller_rabin(1) is False
    assert _miller_rabin(4) is False

  def test_miller_rabin_larger_primes(self):
    for prime in [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 97, 101]:
      assert _miller_rabin(prime) is True
    for composite in [9, 15, 21, 25, 27, 33, 35, 49, 77, 91, 100, 121]:
      assert _miller_rabin(composite) is False

  def test_encrypt_plaintext_ge_p_raises(self):
    with pytest.raises(ValueError, match="0 < m < p"):
      encrypt(self.pub, self.pub[0])

  def test_encrypt_negative_plaintext_raises(self):
    with pytest.raises(ValueError, match="0 < m < p"):
      encrypt(self.pub, -1)
