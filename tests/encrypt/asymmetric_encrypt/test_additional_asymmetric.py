# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_additional_asymmetric.py
# @time    : 2026/3/15 12:00 Sun
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for ECC, DSA, and Diffie-Hellman asymmetric algorithms
"""
Comprehensive tests for additional asymmetric encryption algorithms:
- ECC (Elliptic Curve Cryptography)
- DSA (Digital Signature Algorithm)
- Diffie-Hellman Key Exchange
"""


class TestECC:
  """Tests for Elliptic Curve Cryptography."""

  def test_key_generation(self):
    """Test ECC key pair generation."""
    from crypt.encrypt.asymmetric_encrypt.ecc import N, Point, generate_keypair

    private_key, public_key = generate_keypair()

    # Check private key is in valid range
    assert 1 <= private_key < N

    # Check public key is a valid Point
    assert isinstance(public_key, Point)
    assert not public_key.infinity
    assert isinstance(public_key.x, int)
    assert isinstance(public_key.y, int)

  def test_key_generation_unique(self):
    """Test that generated keys are unique."""
    from crypt.encrypt.asymmetric_encrypt.ecc import generate_keypair

    private_key1, public_key1 = generate_keypair()
    private_key2, public_key2 = generate_keypair()

    # Keys should be different
    assert private_key1 != private_key2
    assert public_key1 != public_key2

  def test_ecdh_key_exchange(self):
    """Test ECDH shared secret generation."""
    from crypt.encrypt.asymmetric_encrypt.ecc import (
      ecdh_shared_secret,
      generate_keypair,
    )

    # Alice generates keypair
    alice_private, alice_public = generate_keypair()

    # Bob generates keypair
    bob_private, bob_public = generate_keypair()

    # Both compute shared secret
    alice_shared = ecdh_shared_secret(alice_private, bob_public)
    bob_shared = ecdh_shared_secret(bob_private, alice_public)

    # Shared secrets should match
    assert alice_shared == bob_shared
    assert len(alice_shared) == 32  # 256 bits = 32 bytes

  def test_ecdsa_sign_verify(self):
    """Test ECDSA sign and verify roundtrip."""
    from crypt.encrypt.asymmetric_encrypt.ecc import (
      ecdsa_sign,
      ecdsa_verify,
      generate_keypair,
    )

    private_key, public_key = generate_keypair()
    message = b"Hello, ECC!"

    # Sign the message
    signature = ecdsa_sign(message, private_key)

    # Verify the signature
    assert ecdsa_verify(message, signature, public_key) is True

  def test_ecdsa_verify_wrong_message(self):
    """Test ECDSA verification fails with wrong message."""
    from crypt.encrypt.asymmetric_encrypt.ecc import (
      ecdsa_sign,
      ecdsa_verify,
      generate_keypair,
    )

    private_key, public_key = generate_keypair()
    message = b"Hello, ECC!"
    wrong_message = b"Wrong message!"

    signature = ecdsa_sign(message, private_key)

    # Verification should fail with wrong message
    assert ecdsa_verify(wrong_message, signature, public_key) is False

  def test_ecdsa_verify_wrong_key(self):
    """Test ECDSA verification fails with wrong public key."""
    from crypt.encrypt.asymmetric_encrypt.ecc import (
      ecdsa_sign,
      ecdsa_verify,
      generate_keypair,
    )

    private_key1, public_key1 = generate_keypair()
    _, public_key2 = generate_keypair()

    message = b"Hello, ECC!"
    signature = ecdsa_sign(message, private_key1)

    # Verification should fail with wrong public key
    assert ecdsa_verify(message, signature, public_key2) is False

  def test_ecdsa_sign_verify_string_message(self):
    """Test ECDSA with string message (auto-encoded)."""
    from crypt.encrypt.asymmetric_encrypt.ecc import (
      ecdsa_sign,
      ecdsa_verify,
      generate_keypair,
    )

    private_key, public_key = generate_keypair()
    message = "Hello, ECC with string!"

    # Sign the string message
    signature = ecdsa_sign(message, private_key)

    # Verify the signature
    assert ecdsa_verify(message, signature, public_key) is True

  def test_ecdsa_signature_components(self):
    """Test that ECDSA signature has valid components."""
    from crypt.encrypt.asymmetric_encrypt.ecc import (
      N,
      ecdsa_sign,
      generate_keypair,
    )

    private_key, _ = generate_keypair()
    message = b"Test message"

    r, s = ecdsa_sign(message, private_key)

    # r and s should be in valid range [1, N-1]
    assert 1 <= r < N
    assert 1 <= s < N


class TestDSA:
  """Tests for Digital Signature Algorithm."""

  def test_key_generation(self):
    """Test DSA key pair generation."""
    from crypt.encrypt.asymmetric_encrypt.dsa import (
      generate_keypair,
      generate_parameters,
    )

    p, q, g = generate_parameters()
    private_key, public_key = generate_keypair(p, q, g)

    # Check private key is in valid range
    assert 1 <= private_key < q

    # Check public key is valid (y = g^x mod p)
    assert isinstance(public_key, int)
    assert 0 <= public_key < p

  def test_key_generation_consistency(self):
    """Test that DSA keys follow the mathematical relationship."""
    from crypt.encrypt.asymmetric_encrypt.dsa import (
      generate_keypair,
      generate_parameters,
    )

    p, q, g = generate_parameters()
    private_key, public_key = generate_keypair(p, q, g)

    # Verify y = g^x mod p
    expected_public = pow(g, private_key, p)
    assert public_key == expected_public

  def test_sign_verify_roundtrip(self):
    """Test DSA sign and verify roundtrip."""
    from crypt.encrypt.asymmetric_encrypt.dsa import (
      generate_keypair,
      generate_parameters,
      sign,
      verify,
    )

    p, q, g = generate_parameters()
    private_key, public_key = generate_keypair(p, q, g)

    message = b"Hello, DSA!"
    signature = sign(message, p, q, g, private_key)

    # Verify the signature
    assert verify(message, signature, p, q, g, public_key) is True

  def test_sign_verify_wrong_message(self):
    """Test DSA verification fails with wrong message."""
    from crypt.encrypt.asymmetric_encrypt.dsa import (
      generate_keypair,
      generate_parameters,
      sign,
      verify,
    )

    p, q, g = generate_parameters()
    private_key, public_key = generate_keypair(p, q, g)

    message = b"Hello, DSA!"
    wrong_message = b"Wrong message!"
    signature = sign(message, p, q, g, private_key)

    # Verification should fail
    assert verify(wrong_message, signature, p, q, g, public_key) is False

  def test_sign_verify_wrong_key(self):
    """Test DSA verification fails with wrong public key."""
    from crypt.encrypt.asymmetric_encrypt.dsa import (
      generate_keypair,
      generate_parameters,
      sign,
      verify,
    )

    p, q, g = generate_parameters()
    private_key1, _ = generate_keypair(p, q, g)
    _, public_key2 = generate_keypair(p, q, g)

    message = b"Hello, DSA!"
    signature = sign(message, p, q, g, private_key1)

    # Verification should fail with wrong public key
    assert verify(message, signature, p, q, g, public_key2) is False

  def test_sign_verify_string_message(self):
    """Test DSA with string message (auto-encoded)."""
    from crypt.encrypt.asymmetric_encrypt.dsa import (
      generate_keypair,
      generate_parameters,
      sign,
      verify,
    )

    p, q, g = generate_parameters()
    private_key, public_key = generate_keypair(p, q, g)

    message = "Hello, DSA with string!"
    signature = sign(message, p, q, g, private_key)

    # Verify the signature
    assert verify(message, signature, p, q, g, public_key) is True

  def test_signature_components(self):
    """Test that DSA signature has valid components."""
    from crypt.encrypt.asymmetric_encrypt.dsa import (
      generate_keypair,
      generate_parameters,
      sign,
    )

    p, q, g = generate_parameters()
    private_key, _ = generate_keypair(p, q, g)

    message = b"Test message"
    r, s = sign(message, p, q, g, private_key)

    # r and s should be in valid range
    assert 0 < r < q
    assert 0 < s < q

  def test_verify_invalid_signature_values(self):
    """Test DSA verification fails with invalid signature values."""
    from crypt.encrypt.asymmetric_encrypt.dsa import (
      generate_keypair,
      generate_parameters,
      verify,
    )

    p, q, g = generate_parameters()
    _, public_key = generate_keypair(p, q, g)

    message = b"Test message"

    # Test with r = 0
    assert verify(message, (0, 1), p, q, g, public_key) is False

    # Test with s = 0
    assert verify(message, (1, 0), p, q, g, public_key) is False

    # Test with r >= q
    assert verify(message, (q, 1), p, q, g, public_key) is False

    # Test with s >= q
    assert verify(message, (1, q), p, q, g, public_key) is False


class TestDiffieHellman:
  """Tests for Diffie-Hellman Key Exchange."""

  def test_key_exchange_same_shared_secret(self):
    """Test that DH key exchange produces same shared secret."""
    from crypt.encrypt.asymmetric_encrypt.diffie_hellman import (
      compute_shared_secret,
      generate_private_key,
      generate_public_key,
    )

    # Alice generates keys
    alice_private = generate_private_key()
    alice_public = generate_public_key(alice_private)

    # Bob generates keys
    bob_private = generate_private_key()
    bob_public = generate_public_key(bob_private)

    # Both compute shared secret
    alice_shared = compute_shared_secret(alice_private, bob_public)
    bob_shared = compute_shared_secret(bob_private, alice_public)

    # Shared secrets should match
    assert alice_shared == bob_shared

  def test_key_exchange_different_private_keys(self):
    """Test that different private keys produce different public keys."""
    from crypt.encrypt.asymmetric_encrypt.diffie_hellman import (
      generate_private_key,
      generate_public_key,
    )

    private_key1 = generate_private_key()
    private_key2 = generate_private_key()

    public_key1 = generate_public_key(private_key1)
    public_key2 = generate_public_key(private_key2)

    # Different private keys should produce different public keys
    assert private_key1 != private_key2
    assert public_key1 != public_key2

  def test_key_exchange_consistency(self):
    """Test DH consistency - same inputs produce same output."""
    from crypt.encrypt.asymmetric_encrypt.diffie_hellman import (
      compute_shared_secret,
    )

    # Use fixed values for consistency test
    private_key_a = 123456789
    private_key_b = 987654321

    # Compute g^a mod p and g^b mod p
    from crypt.encrypt.asymmetric_encrypt.diffie_hellman import G, P

    public_key_a = pow(G, private_key_a, P)
    public_key_b = pow(G, private_key_b, P)

    # Compute shared secrets
    shared_a = compute_shared_secret(private_key_a, public_key_b)
    shared_b = compute_shared_secret(private_key_b, public_key_a)

    # Both should equal g^(ab) mod p
    assert shared_a == shared_b
    assert shared_a == pow(G, private_key_a * private_key_b, P)

  def test_default_parameters(self):
    """Test DH with default RFC 3526 parameters."""
    from crypt.encrypt.asymmetric_encrypt.diffie_hellman import (
      G,
      P,
      compute_shared_secret,
      generate_private_key,
      generate_public_key,
    )

    # Verify default parameters are set
    assert P > 0
    assert G > 0

    # Test key generation with defaults
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)

    # Verify public key calculation
    expected_public = pow(G, private_key, P)
    assert public_key == expected_public

    # Test shared secret computation
    shared = compute_shared_secret(private_key, public_key)
    expected_shared = pow(public_key, private_key, P)
    assert shared == expected_shared

  def test_custom_parameters(self):
    """Test DH with custom parameters."""
    from crypt.encrypt.asymmetric_encrypt.diffie_hellman import (
      compute_shared_secret,
      generate_private_key,
      generate_public_key,
    )

    # Use smaller custom parameters for testing
    custom_p = 23  # Small prime
    custom_g = 5

    private_key = generate_private_key(bits=8)  # Small key for testing
    public_key = generate_public_key(private_key, p=custom_p, g=custom_g)

    # Verify public key calculation
    expected_public = pow(custom_g, private_key, custom_p)
    assert public_key == expected_public

    # Test shared secret
    shared = compute_shared_secret(private_key, public_key, p=custom_p)
    expected_shared = pow(public_key, private_key, custom_p)
    assert shared == expected_shared

  def test_multiple_exchanges_unique_secrets(self):
    """Test that different key exchanges produce different secrets."""
    from crypt.encrypt.asymmetric_encrypt.diffie_hellman import (
      compute_shared_secret,
      generate_private_key,
      generate_public_key,
    )

    # First exchange
    alice_private1 = generate_private_key()
    bob_private1 = generate_private_key()
    alice_public1 = generate_public_key(alice_private1)
    bob_public1 = generate_public_key(bob_private1)
    shared1 = compute_shared_secret(alice_private1, bob_public1)

    # Second exchange
    alice_private2 = generate_private_key()
    bob_private2 = generate_private_key()
    alice_public2 = generate_public_key(alice_private2)
    bob_public2 = generate_public_key(bob_private2)
    shared2 = compute_shared_secret(alice_private2, bob_public2)

    # Different exchanges should produce different secrets
    assert shared1 != shared2
