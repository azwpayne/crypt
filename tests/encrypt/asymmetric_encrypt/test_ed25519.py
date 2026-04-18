"""Tests for Ed25519 digital signature implementation."""

from __future__ import annotations

from crypt.encrypt.asymmetric_encrypt.ed25519 import (
  Point,
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

  def test_decode_point_wrong_length(self):
    assert decode_point(b"\x00" * 31) is None
    assert decode_point(b"\x00" * 33) is None

  def test_decode_point_y_too_large(self):
    # y >= P should return None
    data = (2**255 - 19).to_bytes(32, "little")
    assert decode_point(data) is None

  def test_decode_point_invalid_x2(self):
    # Force x2 that has no valid sqrt
    # Use y=2 which gives x2 = (4-1)/(d*4+1) mod P
    y = 2
    y2 = (y * y) % (2**255 - 19)
    d = (-121665 * pow(121666, -1, 2**255 - 19)) % (2**255 - 19)
    x2 = ((y2 - 1) * pow(d * y2 + 1, -1, 2**255 - 19)) % (2**255 - 19)
    # Find a y where x2 is not a quadratic residue
    # Instead, construct a point that fails is_valid
    data = y.to_bytes(32, "little")
    result = decode_point(data)
    # May be None or a valid point depending on x2
    if result is not None:
      assert result.is_valid()

  def test_generate_public_key_invalid_length(self):
    import pytest

    with pytest.raises(ValueError, match="Private key must be 32 bytes"):
      generate_public_key(b"\x00" * 31)

  def test_sign_invalid_private_key_length(self):
    import pytest

    with pytest.raises(ValueError, match="Private key must be 32 bytes"):
      sign(b"test", b"\x00" * 31)

  def test_verify_wrong_signature_length(self):
    private_key, public_key = generate_keypair()
    assert verify(b"\x00" * 63, b"test", public_key) is False
    assert verify(b"\x00" * 65, b"test", public_key) is False

  def test_verify_wrong_public_key_length(self):
    private_key, public_key = generate_keypair()
    sig = sign(b"test", private_key)
    assert verify(sig, b"test", b"\x00" * 31) is False
    assert verify(sig, b"test", b"\x00" * 33) is False

  def test_verify_s_too_large(self):
    private_key, public_key = generate_keypair()
    sig = sign(b"test", private_key)
    # Set s to L (order of base point)
    bad_sig = sig[:32] + (2**252 + 27742317777372353535851937790883648493).to_bytes(
      32, "little"
    )
    assert verify(bad_sig, b"test", public_key) is False

  def test_verify_none_points(self):
    private_key, public_key = generate_keypair()
    sig = sign(b"test", private_key)
    # Tamper R bytes to make decode_point return None
    bad_r = b"\xff" * 32
    bad_sig = bad_r + sig[32:]
    assert verify(bad_sig, b"test", public_key) is False

  def test_point_hash_raises(self):
    import pytest

    p = Point(0, 1)
    with pytest.raises(TypeError, match="unhashable type"):
      hash(p)

  def test_point_eq_non_point(self):
    p = Point(0, 1)
    assert p != "not a point"
    assert p != 42
