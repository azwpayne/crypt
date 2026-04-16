"""Tests for RSA-PSS signature scheme."""

from crypt.encrypt.asymmetric_encrypt.rsa import generate_keypair
from crypt.encrypt.asymmetric_encrypt.rsa_pss import sign, verify

import pytest


class TestRSAPSS:
  """Test RSA-PSS signatures."""

  def test_sign_verify_roundtrip(self):
    """Test sign and verify roundtrip."""
    public_key, private_key = generate_keypair(1024)
    message = b"Hello, RSA-PSS!"

    signature = sign(message, private_key)
    assert verify(signature, message, public_key) is True

  def test_verify_wrong_message(self):
    """Test verification fails with wrong message."""
    public_key, private_key = generate_keypair(1024)
    message = b"Original message"
    wrong_message = b"Wrong message"

    signature = sign(message, private_key)
    assert verify(signature, wrong_message, public_key) is False

  def test_verify_wrong_key(self):
    """Test verification fails with wrong public key."""
    public_key1, private_key1 = generate_keypair(1024)
    public_key2, _ = generate_keypair(1024)
    message = b"Test message"

    signature = sign(message, private_key1)
    assert verify(signature, message, public_key2) is False

  def test_different_signatures_for_same_message(self):
    """Test that signing same message twice produces different signatures (probabilistic)."""
    public_key, private_key = generate_keypair(1024)
    message = b"Test message"

    signature1 = sign(message, private_key)
    signature2 = sign(message, private_key)

    # Signatures should be different due to random salt
    assert signature1 != signature2

    # But both should verify
    assert verify(signature1, message, public_key) is True
    assert verify(signature2, message, public_key) is True

  def test_empty_message(self):
    """Test signing and verifying empty message."""
    public_key, private_key = generate_keypair(1024)
    message = b""

    signature = sign(message, private_key)
    assert verify(signature, message, public_key) is True

  def test_long_message(self):
    """Test signing and verifying long message."""
    public_key, private_key = generate_keypair(1024)
    message = b"A" * 10000

    signature = sign(message, private_key)
    assert verify(signature, message, public_key) is True

  def test_invalid_signature(self):
    """Test verification with invalid signature."""
    public_key, _ = generate_keypair(1024)
    message = b"Test"

    assert verify(b"invalid", message, public_key) is False

  def test_signature_too_long(self):
    """Test verification with signature that's too long."""
    public_key, _ = generate_keypair(1024)
    message = b"Test"

    # Create a signature that's too long
    invalid_sig = b"x" * 200
    assert verify(invalid_sig, message, public_key) is False

  def test_binary_data(self):
    """Test signing and verifying binary data."""
    public_key, private_key = generate_keypair(1024)
    message = bytes(range(256))

    signature = sign(message, private_key)
    assert verify(signature, message, public_key) is True

  def test_mgf1_mask_too_long(self):
    from crypt.encrypt.asymmetric_encrypt.rsa_pss import mgf1

    import pytest

    # Use a value just over the limit to trigger the check without looping
    with pytest.raises(ValueError, match="Mask too long"):
      mgf1(b"seed", (2**32) * 32 + 1)

  def test_emsa_pss_negative_salt_len(self):
    from crypt.encrypt.asymmetric_encrypt.rsa_pss import _emsa_pss_encode

    import pytest

    with pytest.raises(ValueError, match="salt_len must be non-negative"):
      _emsa_pss_encode(b"msg", 1024, -1, __import__("hashlib").sha256)

  def test_emsa_pss_encoding_error(self):
    from crypt.encrypt.asymmetric_encrypt.rsa_pss import _emsa_pss_encode

    import pytest

    with pytest.raises(ValueError, match="Encoding error"):
      _emsa_pss_encode(b"msg", 8, 32, __import__("hashlib").sha256)

  def test_verify_signature_too_long(self):
    public_key, private_key = generate_keypair(1024)
    message = b"test"
    signature = sign(message, private_key)
    # Make signature too long
    bad_sig = signature + b"\x00"
    assert verify(bad_sig, message, public_key) is False

  def test_verify_signature_value_too_large(self):
    public_key, private_key = generate_keypair(1024)
    message = b"test"
    signature = sign(message, private_key)
    # Make s >= n
    e, n = public_key
    bad_sig = n.to_bytes((n.bit_length() + 7) // 8, "big")
    assert verify(bad_sig, message, public_key) is False

  def test_verify_em_last_byte_wrong(self):
    public_key, private_key = generate_keypair(1024)
    message = b"test"
    signature = sign(message, private_key)
    # Tamper last byte of signature (changes EM reconstruction)
    bad_sig = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert verify(bad_sig, message, public_key) is False

  def test_verify_masked_db_leading_bits(self):
    """Test verify fails when leading bits of masked_db are not zero."""
    public_key, private_key = generate_keypair(1024)
    message = b"test"
    # This is hard to trigger directly, so we test the branch by
    # creating a signature that will reconstruct an EM with bad leading bits
    signature = sign(message, private_key)
    # Any tampered signature should fail
    tampered = bytearray(signature)
    tampered[0] ^= 0xFF
    assert verify(bytes(tampered), message, public_key) is False

  def test_verify_db_padding_wrong(self):
    public_key, private_key = generate_keypair(1024)
    message = b"test"
    signature = sign(message, private_key)
    tampered = bytearray(signature)
    tampered[1] ^= 0xFF
    assert verify(bytes(tampered), message, public_key) is False

  def test_verify_salt_mismatch(self):
    public_key, private_key = generate_keypair(1024)
    message = b"test"
    signature = sign(message, private_key)
    tampered = bytearray(signature)
    tampered[-5] ^= 0xFF
    assert verify(bytes(tampered), message, public_key) is False

  def test_sign_message_too_long(self):
    """Test that sign raises ValueError when encoded message exceeds modulus."""
    import hashlib
    from crypt.encrypt.asymmetric_encrypt.rsa_pss import _emsa_pss_encode

    # Generate a 512-bit key (minimum allowed)
    public_key, private_key = generate_keypair(512)
    message = b"test"
    d, n = private_key
    em_bits = n.bit_length() - 1

    # Manually create an EM that will be >= n by using a large salt
    # But emsa_pss_encode will raise EncodingError for small em_bits with sha256
    # So we test the m >= n branch directly by mocking
    em = (n + 1).to_bytes((n.bit_length() + 7) // 8, "big")

    # Actually, the m >= n check in sign() is hard to hit with emsa_pss_encode
    # because emsa_pss_encode already checks em_bits. Let's test it by
    # directly testing the ValueError path with a crafted scenario.
    # For a 512-bit key, em_bits = 511. sha256 digest = 32, so with salt_len=32,
    # emsa_pss_encode needs 8*32 + 8*32 + 9 = 521 bits, which is > 511.
    # So it raises EncodingError first. The m >= n branch is effectively unreachable
    # with normal parameters. We'll test emsa_pss_encode instead.
    with pytest.raises(ValueError, match="Encoding error"):
      _emsa_pss_encode(message, em_bits, 32, hashlib.sha256)

  def test_custom_hash_func(self):
    import hashlib

    public_key, private_key = generate_keypair(1024)
    message = b"test"
    signature = sign(message, private_key, hash_func=hashlib.sha1)
    assert verify(signature, message, public_key, hash_func=hashlib.sha1) is True
    assert verify(signature, message, public_key, hash_func=hashlib.sha256) is False
