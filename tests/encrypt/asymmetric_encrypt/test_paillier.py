"""Tests for Paillier homomorphic encryption."""

from crypt.encrypt.asymmetric_encrypt.paillier import (
  add_constant,
  add_encrypted,
  decrypt,
  encrypt,
  generate_keypair,
)


class TestPaillier:
  def setup_method(self):
    # Use small keys for test speed
    self.pub, self.priv = generate_keypair(bits=256)

  def test_keypair_structure(self):
    n, g = self.pub
    lam, mu = self.priv
    assert n > 0
    assert g > 0
    assert lam > 0
    assert mu > 0

  def test_encrypt_decrypt_roundtrip(self):
    m = 42
    ct = encrypt(self.pub, m)
    assert decrypt(self.pub, self.priv, ct) == m

  def test_encrypt_zero(self):
    ct = encrypt(self.pub, 0)
    assert decrypt(self.pub, self.priv, ct) == 0

  def test_encrypt_is_probabilistic(self):
    ct1 = encrypt(self.pub, 7)
    ct2 = encrypt(self.pub, 7)
    assert ct1 != ct2

  def test_homomorphic_addition(self):
    a, b = 15, 27
    ct_a = encrypt(self.pub, a)
    ct_b = encrypt(self.pub, b)
    ct_sum = add_encrypted(self.pub, ct_a, ct_b)
    assert decrypt(self.pub, self.priv, ct_sum) == a + b

  def test_add_constant(self):
    a, k = 10, 5
    ct = encrypt(self.pub, a)
    ct_k = add_constant(self.pub, ct, k)
    assert decrypt(self.pub, self.priv, ct_k) == a + k
