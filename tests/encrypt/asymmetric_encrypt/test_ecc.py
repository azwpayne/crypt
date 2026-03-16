"""Tests for ECC (Elliptic Curve Cryptography)."""

from __future__ import annotations

from crypt.encrypt.asymmetric_encrypt import ecc


class TestECC:
  """Test ECC implementation."""

  def test_key_generation(self) -> None:
    """Test ECC key pair generation."""
    private_key, public_key = ecc.generate_keypair()

    # Verify private key is in valid range
    assert 1 <= private_key < ecc.N
    # Verify public key is on the curve
    assert not public_key.infinity

  def test_ecdh_shared_secret(self) -> None:
    """Test ECDH shared secret computation."""
    # Alice's keypair
    alice_private, alice_public = ecc.generate_keypair()
    # Bob's keypair
    bob_private, bob_public = ecc.generate_keypair()

    # Compute shared secrets
    alice_shared = ecc.ecdh_shared_secret(alice_private, bob_public)
    bob_shared = ecc.ecdh_shared_secret(bob_private, alice_public)

    # Both should be equal
    assert alice_shared == bob_shared
    assert len(alice_shared) == 32

  def test_ecdsa_sign_verify(self) -> None:
    """Test ECDSA signing and verification."""
    private_key, public_key = ecc.generate_keypair()

    message = b"Hello, ECC!"
    signature = ecc.ecdsa_sign(message, private_key)

    # Verify signature
    assert ecc.ecdsa_verify(message, signature, public_key)

  def test_ecdsa_verify_invalid_signature(self) -> None:
    """Test ECDSA verification with invalid signature."""
    private_key, public_key = ecc.generate_keypair()

    message = b"Hello, ECC!"
    signature = ecc.ecdsa_sign(message, private_key)

    # Verify with wrong message
    assert not ecc.ecdsa_verify(b"Wrong message", signature, public_key)

  def test_ecdsa_sign_verify_empty_message(self) -> None:
    """Test ECDSA with empty message."""
    private_key, public_key = ecc.generate_keypair()

    message = b""
    signature = ecc.ecdsa_sign(message, private_key)

    assert ecc.ecdsa_verify(message, signature, public_key)

  def test_scalar_mult_identity(self) -> None:
    """Test scalar multiplication with identity."""
    G = ecc.Point(ecc.Gx, ecc.Gy)

    # 1 * G = G
    result = ecc.scalar_mult(1, G)
    assert result == G

  def test_point_addition(self) -> None:
    """Test point addition."""
    G = ecc.Point(ecc.Gx, ecc.Gy)

    # G + (-G) = infinity
    neg_G = ecc.Point(ecc.Gx, (-ecc.Gy) % ecc.P)
    result = ecc.point_add(G, neg_G)
    assert result.infinity

  def test_signature_format(self) -> None:
    """Test signature format."""
    private_key, public_key = ecc.generate_keypair()

    message = b"Test message"
    r, s = ecc.ecdsa_sign(message, private_key)

    # Signature components should be integers in valid range
    assert isinstance(r, int)
    assert isinstance(s, int)
    assert 1 <= r < ecc.N
    assert 1 <= s < ecc.N
