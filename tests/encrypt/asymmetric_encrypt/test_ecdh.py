"""Tests for ECDH key exchange with NIST curves."""

from crypt.encrypt.asymmetric_encrypt.ecdh import (
  CURVES,
  Point,
  compute_shared_secret,
  generate_keypair,
  scalar_mult,
)

import pytest


class TestECDH:
  """Test ECDH key exchange."""

  def test_available_curves(self):
    """Test that expected curves are available."""
    assert "P-256" in CURVES
    assert "P-384" in CURVES
    assert "P-521" in CURVES
    assert "secp256r1" in CURVES
    assert "secp384r1" in CURVES
    assert "secp521r1" in CURVES

  @pytest.mark.parametrize("curve_name", ["P-256", "P-384", "P-521"])
  def test_key_generation(self, curve_name):
    """Test key pair generation for each curve."""
    private_key, public_key = generate_keypair(curve_name)
    assert isinstance(private_key, int)
    assert isinstance(public_key, Point)
    assert public_key.is_valid()

  @pytest.mark.parametrize("curve_name", ["P-256", "P-384", "P-521"])
  def test_shared_secret_agreement(self, curve_name):
    """Test that two parties agree on shared secret."""
    # Alice's keys
    alice_private, alice_public = generate_keypair(curve_name)

    # Bob's keys
    bob_private, bob_public = generate_keypair(curve_name)

    # Compute shared secrets
    alice_shared = compute_shared_secret(alice_private, bob_public)
    bob_shared = compute_shared_secret(bob_private, alice_public)

    assert alice_shared == bob_shared

  @pytest.mark.parametrize("curve_name", ["P-256", "P-384", "P-521"])
  def test_different_keys_different_secrets(self, curve_name):
    """Test that different keys produce different secrets."""
    private1, public1 = generate_keypair(curve_name)
    private2, public2 = generate_keypair(curve_name)
    private3, public3 = generate_keypair(curve_name)

    shared1 = compute_shared_secret(private1, public2)
    shared2 = compute_shared_secret(private1, public3)

    assert shared1 != shared2

  def test_invalid_curve_name(self):
    """Test that invalid curve name raises error."""
    with pytest.raises(ValueError, match="Unsupported curve|Unknown curve|invalid"):
      generate_keypair("invalid-curve")

  def test_point_equality(self):
    """Test point equality comparison."""
    _, public1 = generate_keypair("P-256")
    _, public2 = generate_keypair("P-256")

    public1_copy = public1
    assert public1 == public1_copy
    assert public1 != public2
    assert public1 != "not a point"

  def test_scalar_mult_identity(self):
    """Test scalar multiplication with identity."""
    private, public = generate_keypair("P-256")

    # Multiply by 1 should give same point
    result = scalar_mult(1, public)
    assert result == public

  @pytest.mark.parametrize("curve_name", ["P-256", "P-384", "P-521"])
  def test_shared_secret_length(self, curve_name):
    """Test that shared secret has correct length."""
    private1, public1 = generate_keypair(curve_name)
    private2, public2 = generate_keypair(curve_name)

    shared = compute_shared_secret(private1, public2)
    curve = CURVES[curve_name]
    expected_len = (curve.p.bit_length() + 7) // 8
    assert len(shared) == expected_len

  def test_base_point_validity(self):
    """Test that base points are valid."""
    for name, curve in CURVES.items():
      if name.startswith("secp"):
        continue  # Skip aliases
      base = Point(curve.Gx, curve.Gy, curve)
      assert base.is_valid(), f"Base point for {name} should be valid"
