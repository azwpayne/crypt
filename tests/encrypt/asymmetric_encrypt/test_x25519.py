"""Tests for X25519 ECDH key exchange."""

from crypt.encrypt.asymmetric_encrypt.x25519 import (
  compute_shared_secret,
  generate_private_key,
  generate_public_key,
)

import pytest


class TestX25519:
  """Test X25519 key exchange."""

  def test_key_generation(self):
    """Test private key generation."""
    private_key = generate_private_key()
    assert len(private_key) == 32

  def test_public_key_generation(self):
    """Test public key generation from private key."""
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    assert len(public_key) == 32

  def test_shared_secret_agreement(self):
    """Test that two parties can agree on a shared secret."""
    # Alice's keys
    alice_private = generate_private_key()
    alice_public = generate_public_key(alice_private)

    # Bob's keys
    bob_private = generate_private_key()
    bob_public = generate_public_key(bob_private)

    # Compute shared secrets
    alice_shared = compute_shared_secret(alice_private, bob_public)
    bob_shared = compute_shared_secret(bob_private, alice_public)

    assert len(alice_shared) == 32
    assert len(bob_shared) == 32
    assert alice_shared == bob_shared

  def test_different_keys_different_secrets(self):
    """Test that different keys produce different secrets."""
    private1 = generate_private_key()
    public1 = generate_public_key(private1)

    private2 = generate_private_key()
    public2 = generate_public_key(private2)

    private3 = generate_private_key()
    public3 = generate_public_key(private3)

    shared1 = compute_shared_secret(private1, public2)
    shared2 = compute_shared_secret(private1, public3)

    assert shared1 != shared2

  def test_rfc7748_test_vector_1(self):
    """Test RFC 7748 test vector 1."""
    # Alice's private key
    alice_private = bytes(
      [
        0x77,
        0x07,
        0x6D,
        0x0A,
        0x73,
        0x18,
        0xA5,
        0x7D,
        0x3C,
        0x16,
        0xC1,
        0x72,
        0x51,
        0xB2,
        0x66,
        0x45,
        0xDF,
        0x4C,
        0x2F,
        0x87,
        0xEB,
        0xC0,
        0x99,
        0x2A,
        0xB1,
        0x77,
        0xFB,
        0xA5,
        0x1D,
        0xB9,
        0x2C,
        0x2A,
      ]
    )

    expected_public = bytes(
      [
        0x85,
        0x20,
        0xF0,
        0x09,
        0x89,
        0x30,
        0xA7,
        0x54,
        0x74,
        0x8B,
        0x7D,
        0xDC,
        0xB4,
        0x3E,
        0xF7,
        0x5A,
        0x0D,
        0xBF,
        0x3A,
        0x0D,
        0x26,
        0x38,
        0x1A,
        0xF4,
        0xEB,
        0xA4,
        0xA9,
        0x8E,
        0xAA,
        0x9B,
        0x4E,
        0x6A,
      ]
    )

    public_key = generate_public_key(alice_private)
    assert public_key == expected_public

  def test_rfc7748_test_vector_2(self):
    """Test RFC 7748 test vector 2 (Bob's keys)."""
    bob_private = bytes(
      [
        0x5D,
        0xAB,
        0x08,
        0x7E,
        0x62,
        0x4A,
        0x8A,
        0x4B,
        0x79,
        0xE1,
        0x7F,
        0x8B,
        0x83,
        0x80,
        0x0E,
        0xE6,
        0x6F,
        0x3B,
        0xB1,
        0x29,
        0x26,
        0x18,
        0xB6,
        0xFD,
        0x1C,
        0x2F,
        0x8B,
        0x27,
        0xFF,
        0x88,
        0xE0,
        0xEB,
      ]
    )

    expected_public = bytes(
      [
        0xDE,
        0x9E,
        0xDB,
        0x7D,
        0x7B,
        0x7D,
        0xC1,
        0xB4,
        0xD3,
        0x5B,
        0x61,
        0xC2,
        0xEC,
        0xE4,
        0x35,
        0x37,
        0x3F,
        0x83,
        0x43,
        0xC8,
        0x5B,
        0x78,
        0x67,
        0x4D,
        0xAD,
        0xFC,
        0x7E,
        0x14,
        0x6F,
        0x88,
        0x2B,
        0x4F,
      ]
    )

    public_key = generate_public_key(bob_private)
    assert public_key == expected_public

  def test_rfc7748_shared_secret(self):
    """Test RFC 7748 shared secret computation."""
    alice_private = bytes(
      [
        0x77,
        0x07,
        0x6D,
        0x0A,
        0x73,
        0x18,
        0xA5,
        0x7D,
        0x3C,
        0x16,
        0xC1,
        0x72,
        0x51,
        0xB2,
        0x66,
        0x45,
        0xDF,
        0x4C,
        0x2F,
        0x87,
        0xEB,
        0xC0,
        0x99,
        0x2A,
        0xB1,
        0x77,
        0xFB,
        0xA5,
        0x1D,
        0xB9,
        0x2C,
        0x2A,
      ]
    )

    bob_public = bytes(
      [
        0xDE,
        0x9E,
        0xDB,
        0x7D,
        0x7B,
        0x7D,
        0xC1,
        0xB4,
        0xD3,
        0x5B,
        0x61,
        0xC2,
        0xEC,
        0xE4,
        0x35,
        0x37,
        0x3F,
        0x83,
        0x43,
        0xC8,
        0x5B,
        0x78,
        0x67,
        0x4D,
        0xAD,
        0xFC,
        0x7E,
        0x14,
        0x6F,
        0x88,
        0x2B,
        0x4F,
      ]
    )

    expected_shared = bytes(
      [
        0x4A,
        0x5D,
        0x9D,
        0x5B,
        0xA4,
        0xCE,
        0x2D,
        0xE1,
        0x72,
        0x8E,
        0x3B,
        0xF4,
        0x80,
        0x35,
        0x0F,
        0x25,
        0xE0,
        0x7E,
        0x21,
        0xC9,
        0x47,
        0xD1,
        0x9E,
        0x33,
        0x76,
        0xF0,
        0x9B,
        0x3C,
        0x1E,
        0x16,
        0x17,
        0x42,
      ]
    )

    shared = compute_shared_secret(alice_private, bob_public)
    assert shared == expected_shared

  def test_invalid_private_key_length(self):
    """Test that invalid private key length raises error."""
    with pytest.raises(ValueError, match="32"):
      generate_public_key(b"short")

    with pytest.raises(ValueError, match="32"):
      generate_public_key(b"x" * 33)

  def test_invalid_public_key_length(self):
    """Test that invalid public key length raises error."""
    private_key = generate_private_key()
    with pytest.raises(ValueError, match="32"):
      compute_shared_secret(private_key, b"short")

    with pytest.raises(ValueError, match="32"):
      compute_shared_secret(private_key, b"x" * 33)
