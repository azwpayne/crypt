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

  def test_encrypt_out_of_range_negative(self):
    import pytest

    n, _g = self.pub
    with pytest.raises(ValueError, match="Plaintext must satisfy"):
      encrypt(self.pub, -1)

  def test_encrypt_out_of_range_too_large(self):
    import pytest

    n, _g = self.pub
    with pytest.raises(ValueError, match="Plaintext must satisfy"):
      encrypt(self.pub, n)

  def test_miller_rabin_small_primes(self):
    from crypt.encrypt.asymmetric_encrypt.paillier import _miller_rabin

    assert _miller_rabin(0) is False
    assert _miller_rabin(1) is False
    assert _miller_rabin(2) is True
    assert _miller_rabin(3) is True
    assert _miller_rabin(4) is False

  def test_generate_prime_p_equals_q_loop(self):
    """Test that p==q triggers retry loop."""
    from crypt.encrypt.asymmetric_encrypt.paillier import generate_keypair
    from unittest.mock import patch

    with patch("crypt.encrypt.asymmetric_encrypt.paillier._generate_prime") as mock_gen:
      mock_gen.side_effect = [7, 7, 5, 7]  # First two equal, second pair different
      pub, priv = generate_keypair(bits=8)
      n, g = pub
      assert n == 35  # 5 * 7

  def test_encrypt_r_loop(self):
    """Test encrypt retry loop when gcd(r, n) != 1."""
    from crypt.encrypt.asymmetric_encrypt.paillier import encrypt
    from unittest.mock import patch

    n, g = self.pub
    with patch("secrets.randbelow") as mock_rand:
      mock_rand.side_effect = [0, n - 1]  # First r=0 (gcd(0,n)=n), second r=n-1 (gcd=1)
      ct = encrypt(self.pub, 1)
      assert ct is not None
      assert mock_rand.call_count == 2
