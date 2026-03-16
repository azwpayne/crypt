"""Tests for Ed25519 signature algorithm."""

import pytest

from crypt.encrypt.asymmetric_encrypt.ed25519 import (
    generate_keypair,
    generate_public_key,
    sign,
    verify,
)


class TestEd25519:
    """Test Ed25519 signature algorithm."""

    def test_key_generation(self):
        """Test key pair generation."""
        private_key, public_key = generate_keypair()
        assert len(private_key) == 32
        assert len(public_key) == 32

    def test_public_key_derivation(self):
        """Test that public key can be derived from private key."""
        private_key, public_key = generate_keypair()
        derived_public = generate_public_key(private_key)
        assert derived_public == public_key

    def test_sign_verify_roundtrip(self):
        """Test sign and verify roundtrip."""
        private_key, public_key = generate_keypair()
        message = b"Hello, Ed25519!"

        signature = sign(message, private_key)
        assert len(signature) == 64

        assert verify(signature, message, public_key) is True

    def test_verify_wrong_message(self):
        """Test verification fails with wrong message."""
        private_key, public_key = generate_keypair()
        message = b"Original message"
        wrong_message = b"Wrong message"

        signature = sign(message, private_key)
        assert verify(signature, wrong_message, public_key) is False

    def test_verify_wrong_key(self):
        """Test verification fails with wrong public key."""
        private_key1, public_key1 = generate_keypair()
        _, public_key2 = generate_keypair()
        message = b"Test message"

        signature = sign(message, private_key1)
        assert verify(signature, message, public_key2) is False

    def test_empty_message(self):
        """Test signing and verifying empty message."""
        private_key, public_key = generate_keypair()
        message = b""

        signature = sign(message, private_key)
        assert verify(signature, message, public_key) is True

    def test_long_message(self):
        """Test signing and verifying long message."""
        private_key, public_key = generate_keypair()
        message = b"A" * 10000

        signature = sign(message, private_key)
        assert verify(signature, message, public_key) is True

    def test_invalid_signature_length(self):
        """Test verification with invalid signature length."""
        _, public_key = generate_keypair()
        message = b"Test"

        assert verify(b"short", message, public_key) is False
        assert verify(b"x" * 63, message, public_key) is False
        assert verify(b"x" * 65, message, public_key) is False

    def test_invalid_public_key_length(self):
        """Test verification with invalid public key length."""
        private_key, _ = generate_keypair()
        message = b"Test"
        signature = sign(message, private_key)

        assert verify(signature, message, b"short") is False

    def test_rfc8032_test_vector_1(self):
        """Test RFC 8032 test vector 1."""
        # This is a known test vector from RFC 8032
        private_key = bytes([0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
                             0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                             0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
                             0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60])
        message = b""

        # Generate expected public key
        public_key = generate_public_key(private_key)

        # Sign and verify
        signature = sign(message, private_key)
        assert verify(signature, message, public_key) is True

    def test_rfc8032_test_vector_2(self):
        """Test RFC 8032 test vector 2."""
        private_key = bytes([0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
                             0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
                             0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0xdf,
                             0x0f, 0x1a, 0xa1, 0x35, 0x31, 0x15, 0x92, 0xf7])
        message = b"\x72"

        public_key = generate_public_key(private_key)
        signature = sign(message, private_key)
        assert verify(signature, message, public_key) is True

    def test_binary_data(self):
        """Test signing and verifying binary data."""
        private_key, public_key = generate_keypair()
        message = bytes(range(256))

        signature = sign(message, private_key)
        assert verify(signature, message, public_key) is True
