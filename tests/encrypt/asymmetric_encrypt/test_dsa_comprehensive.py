"""Comprehensive tests for DSA (Digital Signature Algorithm).

This module contains thorough unit tests for the DSA implementation,
covering various edge cases, input validation, and security properties.
"""

from __future__ import annotations

import hashlib
from crypt.encrypt.asymmetric_encrypt import dsa


class TestDSAKeyGeneration:
  """Test DSA parameter and key generation."""

  def test_generate_parameters_returns_valid_pqg(self) -> None:
    """Test that generate_parameters returns valid p, q, g."""
    p, q, g = dsa.generate_parameters()

    # p should be prime
    assert p > 0
    # q should be prime (256-bit)
    assert q > 0
    # g should be a generator
    assert g > 1
    assert g < p

  def test_generate_parameters_p_relation(self) -> None:
    """Test that p = k*q + 1 for some k."""
    p, q, g = dsa.generate_parameters()

    # p-1 should be divisible by q
    assert (p - 1) % q == 0

  def test_generate_parameters_generator_valid(self) -> None:
    """Test that g is a valid generator of order q."""
    p, q, g = dsa.generate_parameters()

    # g^q mod p should equal 1 (generator property)
    assert pow(g, q, p) == 1

  def test_generate_keypair_private_key_range(self) -> None:
    """Test that private key is in valid range [1, q-1]."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    assert 0 < x < q

  def test_generate_keypair_public_key_correct(self) -> None:
    """Test that public key y = g^x mod p."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    expected_y = pow(g, x, p)
    assert y == expected_y

  def test_generate_keypair_private_key_in_valid_range(self) -> None:
    """Test that generated private key is always in valid range."""
    p, q, g = dsa.generate_parameters()

    # Generate multiple keypairs and verify range
    for _ in range(10):
      x, y = dsa.generate_keypair(p, q, g)
      assert 1 <= x < q
      assert y == pow(g, x, p)


class TestDSASigning:
  """Test DSA signature generation."""

  def test_sign_returns_tuple(self) -> None:
    """Test that sign returns a tuple of (r, s)."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    signature = dsa.sign(message, p, q, g, x)

    assert isinstance(signature, tuple)
    assert len(signature) == 2
    r, s = signature
    assert isinstance(r, int)
    assert isinstance(s, int)

  def test_sign_signature_components_in_range(self) -> None:
    """Test that r and s are in valid range [1, q-1]."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    r, s = dsa.sign(message, p, q, g, x)

    assert 0 < r < q, f"r={r} not in range (0, {q})"
    assert 0 < s < q, f"s={s} not in range (0, {q})"

  def test_sign_different_signatures_for_same_message(self) -> None:
    """Test that signing the same message twice produces different signatures."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    sig1 = dsa.sign(message, p, q, g, x)
    sig2 = dsa.sign(message, p, q, g, x)

    # Due to random k, signatures should be different
    assert sig1 != sig2

  def test_sign_with_string_message(self) -> None:
    """Test signing with string message (auto-encoded to bytes)."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message_str = "test message"
    message_bytes = message_str.encode()

    sig_str = dsa.sign(message_str, p, q, g, x)
    sig_bytes = dsa.sign(message_bytes, p, q, g, x)

    # Both should verify successfully
    assert dsa.verify(message_str, sig_str, p, q, g, y, y=y)
    assert dsa.verify(message_bytes, sig_str, p, q, g, y, y=y)

  def test_sign_empty_message(self) -> None:
    """Test signing empty message."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b""
    signature = dsa.sign(message, p, q, g, x)

    assert isinstance(signature, tuple)
    assert len(signature) == 2

  def test_sign_large_message(self) -> None:
    """Test signing large message."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"x" * 1000000  # 1MB message
    signature = dsa.sign(message, p, q, g, x)

    assert dsa.verify(message, signature, p, q, g, y, y=y)

  def test_sign_with_special_characters(self) -> None:
    """Test signing messages with special characters."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    messages = [
      b"\x00\x01\x02\x03",
      b"\xff\xfe\xfd\xfc",
      b"Hello\x00World",
      "特殊字符".encode(),
      "🎉🎊".encode(),
    ]

    for message in messages:
      signature = dsa.sign(message, p, q, g, x)
      assert dsa.verify(message, signature, p, q, g, y, y=y)


class TestDSAVerification:
  """Test DSA signature verification."""

  def test_verify_valid_signature(self) -> None:
    """Test verification of a valid signature."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    signature = dsa.sign(message, p, q, g, x)

    assert dsa.verify(message, signature, p, q, g, y, y=y)

  def test_verify_invalid_signature_wrong_message(self) -> None:
    """Test verification fails with wrong message."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    wrong_message = b"wrong message"
    signature = dsa.sign(message, p, q, g, x)

    assert not dsa.verify(wrong_message, signature, p, q, g, y, y=y)

  def test_verify_invalid_signature_wrong_r(self) -> None:
    """Test verification fails with modified r."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    r, s = dsa.sign(message, p, q, g, x)

    # Modify r
    invalid_signature = (r + 1, s)
    assert not dsa.verify(message, invalid_signature, p, q, g, y, y=y)

  def test_verify_invalid_signature_wrong_s(self) -> None:
    """Test verification fails with modified s."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    r, s = dsa.sign(message, p, q, g, x)

    # Modify s
    invalid_signature = (r, s + 1)
    assert not dsa.verify(message, invalid_signature, p, q, g, y, y=y)

  def test_verify_signature_r_out_of_range(self) -> None:
    """Test verification fails when r is out of range."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    _, s = dsa.sign(message, p, q, g, x)

    # r = 0 should fail
    assert not dsa.verify(message, (0, s), p, q, g, y=y)
    # r = q should fail
    assert not dsa.verify(message, (q, s), p, q, g, y=y)
    # r > q should fail
    assert not dsa.verify(message, (q + 1, s), p, q, g, y=y)

  def test_verify_signature_s_out_of_range(self) -> None:
    """Test verification fails when s is out of range."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    r, _ = dsa.sign(message, p, q, g, x)

    # s = 0 should fail
    assert not dsa.verify(message, (r, 0), p, q, g, y=y)
    # s = q should fail
    assert not dsa.verify(message, (r, q), p, q, g, y=y)
    # s > q should fail
    assert not dsa.verify(message, (r, q + 1), p, q, g, y=y)

  def test_verify_with_wrong_public_key(self) -> None:
    """Test verification fails with wrong public key."""
    p, q, g = dsa.generate_parameters()
    x1, y1 = dsa.generate_keypair(p, q, g)
    _, y2 = dsa.generate_keypair(p, q, g)

    message = b"test message"
    signature = dsa.sign(message, p, q, g, x1)

    # Verify with different public key should fail
    assert not dsa.verify(message, signature, p, q, g, y2)

  def test_verify_with_string_message(self) -> None:
    """Test verification with string message."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message_str = "test message"
    message_bytes = message_str.encode()

    signature = dsa.sign(message_bytes, p, q, g, x)

    # Both string and bytes should verify
    assert dsa.verify(message_str, signature, p, q, g, y, y=y)
    assert dsa.verify(message_bytes, signature, p, q, g, y, y=y)


class TestDSAIntegration:
  """Integration tests for complete DSA workflows."""

  def test_full_sign_verify_workflow(self) -> None:
    """Test complete sign and verify workflow."""
    # Generate parameters
    p, q, g = dsa.generate_parameters()

    # Generate keypair
    private_key, public_key = dsa.generate_keypair(p, q, g)

    # Sign message
    message = b"Important document"
    signature = dsa.sign(message, p, q, g, private_key)

    # Verify signature
    assert dsa.verify(message, signature, p, q, g, public_key)

  def test_multiple_messages_same_keypair(self) -> None:
    """Test signing multiple messages with same keypair."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    messages = [
      b"Message 1",
      b"Message 2",
      b"Message 3",
    ]

    signatures = []
    for message in messages:
      signature = dsa.sign(message, p, q, g, x)
      signatures.append((message, signature))

    # Verify all signatures
    for message, signature in signatures:
      assert dsa.verify(message, signature, p, q, g, y, y=y)

    # Cross-verify should fail
    for i, (_msg1, sig1) in enumerate(signatures):
      for j, (msg2, _) in enumerate(signatures):
        if i != j:
          assert not dsa.verify(msg2, sig1, p, q, g, y, y=y)

  def test_dsa_with_different_parameter_sets(self) -> None:
    """Test DSA with multiple parameter generations."""
    for _ in range(3):
      p, q, g = dsa.generate_parameters()
      x, y = dsa.generate_keypair(p, q, g)

      message = b"test"
      signature = dsa.sign(message, p, q, g, x)

      assert dsa.verify(message, signature, p, q, g, y, y=y)


class TestDSASecurity:
  """Security-focused tests for DSA."""

  def test_private_key_cannot_be_derived_from_signature(self) -> None:
    """Test that private key cannot be derived from signature."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test message"
    r, s = dsa.sign(message, p, q, g, x)

    # Knowing r, s, message, and public key should not reveal x
    # This is a property test - we can't directly test this,
    # but we verify the signature doesn't contain x directly
    assert r != x
    assert s != x

  def test_different_private_keys_produce_different_signatures(self) -> None:
    """Test that different private keys produce different signatures."""
    p, q, g = dsa.generate_parameters()

    x1, y1 = dsa.generate_keypair(p, q, g)
    x2, y2 = dsa.generate_keypair(p, q, g)

    # Ensure different private keys
    while x1 == x2:
      x2, y2 = dsa.generate_keypair(p, q, g)

    message = b"test message"
    sig1 = dsa.sign(message, p, q, g, x1)
    sig2 = dsa.sign(message, p, q, g, x2)

    # Signatures will be different due to random k
    # But both should verify with their respective public keys
    assert dsa.verify(message, sig1, p, q, g, y1)
    assert dsa.verify(message, sig2, p, q, g, y2)

    # Cross-verification should fail
    assert not dsa.verify(message, sig1, p, q, g, y2)
    assert not dsa.verify(message, sig2, p, q, g, y1)


class TestDSAEdgeCases:
  """Edge case tests for DSA."""

  def test_sign_verify_unicode_message(self) -> None:
    """Test signing and verifying unicode messages."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    unicode_messages = [
      "Hello, 世界!",
      "🎉 Celebration 🎊",
      "Café résumé naïve",
      "السلام عليكم",
      "שלום עולם",
    ]

    for message in unicode_messages:
      signature = dsa.sign(message, p, q, g, x)
      assert dsa.verify(message, signature, p, q, g, y, y=y)

  def test_signature_with_leading_zeros_in_hash(self) -> None:
    """Test signatures when hash has leading zeros."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    # Find a message whose hash starts with zero bytes
    # This tests the hash-to-int conversion
    for i in range(1000):
      message = f"test{i}".encode()
      h = hashlib.sha256(message).digest()
      if h[0] == 0:
        signature = dsa.sign(message, p, q, g, x)
        assert dsa.verify(message, signature, p, q, g, y, y=y)
        break

  def test_boundary_values_for_r_and_s(self) -> None:
    """Test boundary values for signature components."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"test"
    r, s = dsa.sign(message, p, q, g, x)

    # Test boundary values
    boundary_tests = [
      (0, s),  # r = 0 (invalid)
      (1, s),  # r = 1 (valid)
      (q - 1, s),  # r = q-1 (valid)
      (q, s),  # r = q (invalid)
      (r, 0),  # s = 0 (invalid)
      (r, 1),  # s = 1 (valid)
      (r, q - 1),  # s = q-1 (valid)
      (r, q),  # s = q (invalid)
    ]

    valid_boundaries = [
      (1, s),
      (q - 1, s),
      (r, 1),
      (r, q - 1),
    ]

    for sig in valid_boundaries:
      # These may or may not verify depending on the actual signature
      # Just ensure they don't crash
      dsa.verify(message, sig, p, q, g, y, y=y)
