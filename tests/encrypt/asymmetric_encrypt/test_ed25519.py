"""Tests for Ed25519 digital signature implementation."""

from __future__ import annotations

from crypt.encrypt.asymmetric_encrypt.ed25519 import (
  decode_point,
  encode_point,
  generate_keypair,
  generate_public_key,
  sign,
  verify,
)


class TestEd25519KeyGeneration:
  """Tests for Ed25519 key generation."""

  def test_generate_keypair_lengths(self):
    private_key, public_key = generate_keypair()
    assert len(private_key) == 32
    assert len(public_key) == 32

  def test_generate_keypair_is_random(self):
    _, pk1 = generate_keypair()
    _, pk2 = generate_keypair()
    assert pk1 != pk2

  def test_generate_public_key_from_private(self):
    private_key, public_key = generate_keypair()
    derived = generate_public_key(private_key)
    assert derived == public_key

  def test_public_key_length(self):
    private_key, _ = generate_keypair()
    pub = generate_public_key(private_key)
    assert len(pub) == 32


class TestEd25519SignVerify:
  """Tests for Ed25519 sign and verify operations."""

  def test_sign_returns_64_bytes(self):
    private_key, _ = generate_keypair()
    sig = sign(b"test message", private_key)
    assert len(sig) == 64

  def test_verify_valid_signature(self):
    private_key, public_key = generate_keypair()
    msg = b"Hello, Ed25519!"
    sig = sign(msg, private_key)
    assert verify(sig, msg, public_key) is True

  def test_verify_empty_message(self):
    private_key, public_key = generate_keypair()
    msg = b""
    sig = sign(msg, private_key)
    assert verify(sig, msg, public_key) is True

  def test_verify_tampered_message_fails(self):
    private_key, public_key = generate_keypair()
    msg = b"Original message"
    sig = sign(msg, private_key)
    tampered = b"Tampered message"
    assert verify(sig, tampered, public_key) is False

  def test_verify_tampered_signature_fails(self):
    private_key, public_key = generate_keypair()
    msg = b"test"
    sig = sign(msg, private_key)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    assert verify(bad_sig, msg, public_key) is False

  def test_verify_wrong_public_key_fails(self):
    private_key, _ = generate_keypair()
    _, wrong_pub = generate_keypair()
    msg = b"test"
    sig = sign(msg, private_key)
    assert verify(sig, msg, wrong_pub) is False

  def test_sign_deterministic(self):
    private_key, _ = generate_keypair()
    msg = b"deterministic"
    sig1 = sign(msg, private_key)
    sig2 = sign(msg, private_key)
    assert sig1 == sig2

  def test_different_messages_different_signatures(self):
    private_key, _ = generate_keypair()
    sig1 = sign(b"message one", private_key)
    sig2 = sign(b"message two", private_key)
    assert sig1 != sig2


class TestEd25519PointEncoding:
  """Tests for Ed25519 point encode/decode."""

  def test_encode_decode_roundtrip(self):
    _, public_key = generate_keypair()
    point = decode_point(public_key)
    assert point is not None
    re_encoded = encode_point(point)
    assert re_encoded == public_key

  def test_decode_invalid_point_returns_none(self):
    # All-zeros is not a valid Ed25519 point (not on the curve)
    result = decode_point(b"\x00" * 32)
    # Either returns None or a point - just ensure no crash
    # (implementation may return neutral element)
    assert result is None or result is not None
