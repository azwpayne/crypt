"""
Comprehensive tests for NTRU post-quantum encryption.
"""

from crypt.encrypt.asymmetric_encrypt.ntru import (
  _bytes_to_poly,
  _center_lift,
  _generate_trinary,
  _int_to_poly,
  _mod_p_reduce,
  _poly_add,
  _poly_mod_inverse,
  _poly_mul,
  _poly_scalar_mul,
  _poly_to_bytes,
  _poly_to_int,
  ntru_decrypt,
  ntru_encrypt,
  ntru_generate_keypair,
)

import pytest

# ── Polynomial arithmetic tests ─────────────────────────────────────────


class TestPolyArithmetic:
  """Tests for low-level polynomial operations."""

  def test_poly_add_basic(self):
    """Test polynomial addition in Z[X]/(X^N - 1)."""
    a = [1, 2, 3, 0, 0]
    b = [4, 5, 6, 0, 0]
    result = _poly_add(a, b, mod=7, n=5)
    assert result == [5, 0, 2, 0, 0]  # (9%7=2, 7%7=0, 9%7=2)

  def test_poly_add_modular_reduction(self):
    """Test that addition properly reduces coefficients mod q."""
    a = [200, 100, 0]
    b = [100, 200, 0]
    result = _poly_add(a, b, mod=256, n=3)
    assert result == [44, 44, 0]  # 300%256=44

  def test_poly_mul_basic(self):
    """Test polynomial multiplication in Z[X]/(X^N - 1)."""
    # (1 + x) * (1 + x) = 1 + 2x + x^2  in Z[X]/(X^3 - 1)
    a = [1, 1, 0]
    b = [1, 1, 0]
    result = _poly_mul(a, b, mod=256, n=3)
    assert result == [1, 2, 1]

  def test_poly_mul_cyclic_wrap(self):
    """Test that multiplication wraps around X^N = 1."""
    # x^(N-1) * x = x^N = 1  in Z[X]/(X^N - 1)
    a = [0, 0, 1]  # x^2
    b = [0, 1, 0]  # x
    result = _poly_mul(a, b, mod=256, n=3)
    assert result == [1, 0, 0]  # x^3 = 1

  def test_poly_mul_zero_polynomial(self):
    """Test multiplication by zero polynomial."""
    a = [1, 2, 3]
    b = [0, 0, 0]
    result = _poly_mul(a, b, mod=256, n=3)
    assert result == [0, 0, 0]

  def test_poly_mul_identity(self):
    """Test multiplication by polynomial 1 (identity)."""
    a = [5, 10, 15]
    b = [1, 0, 0]
    result = _poly_mul(a, b, mod=256, n=3)
    assert result == [5, 10, 15]

  def test_poly_scalar_mul(self):
    """Test scalar multiplication."""
    poly = [1, 2, 3]
    result = _poly_scalar_mul(poly, 3, mod=7, _n=3)
    assert result == [3, 6, 2]  # 9%7=2

  def test_poly_scalar_mul_zero(self):
    """Test scalar multiplication by zero."""
    poly = [1, 2, 3]
    result = _poly_scalar_mul(poly, 0, mod=256, _n=3)
    assert result == [0, 0, 0]


class TestCenterLift:
  """Tests for center-lift operation."""

  def test_center_lift_no_change(self):
    """Test center-lift when coefficients are already in range."""
    poly = [0, 1, 2, -1, -2]
    result = _center_lift(poly, q=8)
    assert result == [0, 1, 2, -1, -2]

  def test_center_lift_positive_overflow(self):
    """Test center-lift with coefficients > q/2."""
    poly = [5, 6, 7]
    result = _center_lift(poly, q=8)
    assert result == [-3, -2, -1]  # 5-8=-3, 6-8=-2, 7-8=-1

  def test_center_lift_mixed(self):
    """Test center-lift with mixed coefficients."""
    poly = [0, 1, 128, 129, 255]
    result = _center_lift(poly, q=256)
    assert result == [0, 1, 128, -127, -1]


class TestModPReduce:
  """Tests for mod-p reduction to balanced representation."""

  def test_mod_p_reduce_p3(self):
    """Test mod-p reduction with p=3."""
    poly = [0, 1, 2, 3, 4, 5]
    result = _mod_p_reduce(poly, p=3)
    # 0%3=0, 1%3=1, 2%3=-1, 3%3=0, 4%3=1, 5%3=-1
    assert result == [0, 1, -1, 0, 1, -1]

  def test_mod_p_reduce_already_reduced(self):
    """Test mod-p reduction when already in balanced form."""
    poly = [0, 1, -1]
    result = _mod_p_reduce(poly, p=3)
    assert result == [0, 1, -1]


class TestPolyModInverse:
  """Tests for polynomial modular inverse."""

  def test_inverse_mod_3(self):
    """Test polynomial inverse mod 3."""
    # f = 1 + x - x^2 (coefficients [1, 1, -1])
    f = [1, 1, -1]
    fp = _poly_mod_inverse(f, mod=3, n=3)
    # Verify: f * fp ≡ 1 (mod 3)
    product = _poly_mul(f, fp, mod=3, n=3)
    assert product[0] == 1
    assert all(c == 0 for c in product[1:])

  def test_inverse_mod_257(self):
    """Test polynomial inverse mod 257 (prime)."""
    f = [1, 1, -1, 0, 0]
    fq = _poly_mod_inverse(f, mod=257, n=5)
    product = _poly_mul(f, fq, mod=257, n=5)
    assert product[0] == 1
    assert all(c == 0 for c in product[1:])

  def test_inverse_mod_prime(self):
    """Test polynomial inverse mod various primes."""
    for mod in [17, 257, 2053]:
      f = [1, 1, -1, 0, 0]
      fq = _poly_mod_inverse(f, mod=mod, n=5)
      product = _poly_mul(f, fq, mod=mod, n=5)
      assert product[0] == 1
      assert all(c == 0 for c in product[1:])


class TestGenerateTrinary:
  """Tests for trinary polynomial generation."""

  def test_correct_number_of_coefficients(self):
    """Test that generated polynomial has correct number of +1 and -1."""
    poly = _generate_trinary(n=50, num_ones=10, num_neg_ones=10)
    assert poly.count(1) == 10
    assert poly.count(-1) == 10
    assert poly.count(0) == 30

  def test_length_matches_n(self):
    """Test that generated polynomial has length n."""
    poly = _generate_trinary(n=251, num_ones=72, num_neg_ones=72)
    assert len(poly) == 251

  def test_all_zeros(self):
    """Test generating polynomial with all zeros."""
    poly = _generate_trinary(n=10, num_ones=0, num_neg_ones=0)
    assert poly == [0] * 10

  def test_exceeds_degree_raises(self):
    """Test that requesting more non-zero coefficients than n raises."""
    with pytest.raises(ValueError, match="exceed"):
      _generate_trinary(n=5, num_ones=3, num_neg_ones=3)

  def test_randomness(self):
    """Test that successive generations produce different polynomials."""
    poly1 = _generate_trinary(n=100, num_ones=30, num_neg_ones=30)
    poly2 = _generate_trinary(n=100, num_ones=30, num_neg_ones=30)
    # With overwhelming probability they should differ
    assert poly1 != poly2


class TestSerialization:
  """Tests for polynomial ↔ bytes serialization."""

  def test_roundtrip_trinary(self):
    """Test that poly_to_bytes → bytes_to_poly is identity for trinary polys."""
    poly = [0, 1, -1, 1, 0, -1, 1, 1, 0, -1]
    data = _poly_to_bytes(poly, p=3)
    recovered = _bytes_to_poly(data, n=len(poly))
    assert recovered == poly

  def test_roundtrip_all_zeros(self):
    """Test roundtrip for all-zero polynomial."""
    poly = [0] * 20
    data = _poly_to_bytes(poly, p=3)
    recovered = _bytes_to_poly(data, n=20)
    assert recovered == poly

  def test_roundtrip_all_ones(self):
    """Test roundtrip for all-ones polynomial."""
    poly = [1] * 16
    data = _poly_to_bytes(poly, p=3)
    recovered = _bytes_to_poly(data, n=16)
    assert recovered == poly

  def test_roundtrip_all_neg_ones(self):
    """Test roundtrip for all-negative-ones polynomial."""
    poly = [-1] * 16
    data = _poly_to_bytes(poly, p=3)
    recovered = _bytes_to_poly(data, n=16)
    assert recovered == poly

  def test_bytes_to_poly_pads_to_n(self):
    """Test that bytes_to_poly pads with zeros when n > decoded length."""
    poly = [1, -1]
    data = _poly_to_bytes(poly, p=3)
    recovered = _bytes_to_poly(data, n=10)
    assert recovered == [1, -1, 0, 0, 0, 0, 0, 0, 0, 0]


class TestIntPolyConversion:
  """Tests for integer ↔ polynomial conversion."""

  def test_roundtrip_small(self):
    """Test int → poly → int roundtrip."""
    value = 42
    poly = _int_to_poly(value, n=10)
    recovered = _poly_to_int(poly)
    assert recovered == value

  def test_roundtrip_zero(self):
    """Test roundtrip for zero."""
    poly = _int_to_poly(0, n=10)
    assert all(c == 0 for c in poly)
    assert _poly_to_int(poly) == 0

  def test_roundtrip_one(self):
    """Test roundtrip for one."""
    poly = _int_to_poly(1, n=10)
    assert poly[0] == 1
    assert all(c == 0 for c in poly[1:])
    assert _poly_to_int(poly) == 1


# ── Key generation tests ────────────────────────────────────────────────


class TestKeyGeneration:
  """Tests for NTRU key generation."""

  def test_keypair_structure(self):
    """Test that key generation produces correctly structured keys."""
    pub, priv = ntru_generate_keypair()

    assert "h" in pub
    assert "n" in pub
    assert "p" in pub
    assert "q" in pub

    assert "f" in priv
    assert "fp" in priv
    assert "n" in priv
    assert "p" in priv
    assert "q" in priv

  def test_default_parameters(self):
    """Test that default parameters are N=251, p=3, q=2053."""
    pub, priv = ntru_generate_keypair()

    assert pub["n"] == 251
    assert pub["p"] == 3
    assert pub["q"] == 2053
    assert priv["n"] == 251
    assert priv["p"] == 3
    assert priv["q"] == 2053

  def test_polynomial_lengths(self):
    """Test that all polynomials have length N."""
    pub, priv = ntru_generate_keypair(n=251)
    n = 251

    assert len(pub["h"]) == n
    assert len(priv["f"]) == n
    assert len(priv["fp"]) == n

  def test_custom_parameters(self):
    """Test key generation with custom parameters."""
    pub, priv = ntru_generate_keypair(n=107, p=3, q=349, df=15, dg=12)

    assert pub["n"] == 107
    assert pub["p"] == 3
    assert pub["q"] == 349
    assert len(pub["h"]) == 107

  def test_f_is_trinary(self):
    """Test that private key f has coefficients in {-1, 0, 1}."""
    _, priv = ntru_generate_keypair()
    f = priv["f"]
    assert all(c in (-1, 0, 1) for c in f)

  def test_fp_is_inverse_of_f_mod_p(self):
    """Test that fp * f ≡ 1 (mod p)."""
    _, priv = ntru_generate_keypair()
    f = priv["f"]
    fp = priv["fp"]
    p = priv["p"]
    n = priv["n"]

    product = _poly_mul(f, fp, mod=p, n=n)
    assert product[0] == 1
    assert all(c == 0 for c in product[1:])

  def test_different_keypairs_each_time(self):
    """Test that successive key generations produce different keys."""
    pub1, priv1 = ntru_generate_keypair()
    pub2, priv2 = ntru_generate_keypair()

    assert pub1["h"] != pub2["h"]
    assert priv1["f"] != priv2["f"]


# ── Encryption / Decryption tests ───────────────────────────────────────


class TestEncryptionDecryption:
  """Tests for NTRU encryption and decryption."""

  def setup_method(self):
    """Generate a fresh key pair for each test."""
    self.pub, self.priv = ntru_generate_keypair()

  def test_encrypt_decrypt_short_message(self):
    """Test encrypt → decrypt roundtrip for a short message."""
    message = b"Hi"
    ciphertext = ntru_encrypt(message, self.pub)
    decrypted = ntru_decrypt(ciphertext, self.priv)
    assert decrypted == message

  def test_encrypt_decrypt_single_byte(self):
    """Test encrypt → decrypt roundtrip for a single byte."""
    message = b"X"
    ciphertext = ntru_encrypt(message, self.pub)
    decrypted = ntru_decrypt(ciphertext, self.priv)
    assert decrypted == message

  def test_encrypt_decrypt_hello_world(self):
    """Test encrypt → decrypt roundtrip for 'Hello, World!'."""
    message = b"Hello, World!"
    ciphertext = ntru_encrypt(message, self.pub)
    decrypted = ntru_decrypt(ciphertext, self.priv)
    assert decrypted == message

  def test_encrypt_produces_correct_length(self):
    """Test that ciphertext has expected length (12-bit packed coefficients)."""
    message = b"test"
    ciphertext = ntru_encrypt(message, self.pub)
    expected_len = (self.pub["n"] * 12 + 7) // 8
    assert len(ciphertext) == expected_len

  def test_encrypt_is_probabilistic(self):
    """Test that encrypting the same message produces different ciphertexts."""
    message = b"Same message"
    ct1 = ntru_encrypt(message, self.pub)
    ct2 = ntru_encrypt(message, self.pub)
    # With overwhelming probability, ciphertexts differ
    assert ct1 != ct2

  def test_decrypt_wrong_key_fails(self):
    """Test that decryption with wrong key does not recover message."""
    message = b"Secret"
    ciphertext = ntru_encrypt(message, self.pub)

    # Generate a different key pair
    other_pub, other_priv = ntru_generate_keypair()
    decrypted = ntru_decrypt(ciphertext, other_priv)

    # Decryption with wrong key should not produce the original message
    # (with overwhelming probability)
    assert decrypted != message

  def test_decrypt_wrong_length_garbage(self):
    """Test that decryption with wrong ciphertext length produces garbage."""
    decrypted = ntru_decrypt(b"\x00" * 100, self.priv)
    message = b"test"
    ciphertext = ntru_encrypt(message, self.pub)
    correct = ntru_decrypt(ciphertext, self.priv)
    # Wrong-length input should not produce the original message
    assert decrypted != correct

  def test_encrypt_decrypt_unicode(self):
    """Test encrypt → decrypt with unicode content."""
    message = "你好世界 🌍".encode()
    ciphertext = ntru_encrypt(message, self.pub)
    decrypted = ntru_decrypt(ciphertext, self.priv)
    assert decrypted == message

  def test_encrypt_decrypt_binary_data(self):
    """Test encrypt → decrypt with arbitrary binary data."""
    message = bytes(range(1, 20))
    ciphertext = ntru_encrypt(message, self.pub)
    decrypted = ntru_decrypt(ciphertext, self.priv)
    assert decrypted == message


class TestEncryptionDecryptionSmallParams:
  """Tests with smaller parameters for faster execution."""

  def test_roundtrip_n107(self):
    """Test encrypt → decrypt with N=107 (smaller, faster)."""
    pub, priv = ntru_generate_keypair(n=107, p=3, q=349, df=15, dg=12)
    message = b"Small params"
    ciphertext = ntru_encrypt(message, pub)
    decrypted = ntru_decrypt(ciphertext, priv)
    assert decrypted == message

  def test_roundtrip_n83(self):
    """Test encrypt → decrypt with N=83 (even smaller)."""
    pub, priv = ntru_generate_keypair(n=83, p=3, q=179, df=10, dg=8)
    message = b"Tiny"
    ciphertext = ntru_encrypt(message, pub)
    decrypted = ntru_decrypt(ciphertext, priv)
    assert decrypted == message


class TestEdgeCases:
  """Tests for edge cases and boundary conditions."""

  def test_multiple_roundtrips_same_keypair(self):
    """Test multiple encrypt/decrypt cycles with the same key pair."""
    pub, priv = ntru_generate_keypair()
    messages = [b"one", b"two", b"three", b"four", b"five"]

    for msg in messages:
      ct = ntru_encrypt(msg, pub)
      pt = ntru_decrypt(ct, priv)
      assert pt == msg

  def test_consistent_decryption(self):
    """Test that decrypting the same ciphertext always gives the same result."""
    pub, priv = ntru_generate_keypair()
    message = b"Consistent"
    ciphertext = ntru_encrypt(message, pub)

    for _ in range(5):
      assert ntru_decrypt(ciphertext, priv) == message


@pytest.mark.parametrize("size", [1, 5, 10, 20, 30])
def test_various_message_sizes(size):
  """Test encrypt/decrypt with various message sizes."""
  pub, priv = ntru_generate_keypair()
  message = b"A" * size
  ciphertext = ntru_encrypt(message, pub)
  decrypted = ntru_decrypt(ciphertext, priv)
  assert decrypted == message
