"""Tests for RSA-PSS signature scheme."""


from crypt.encrypt.asymmetric_encrypt.rsa import generate_keypair
from crypt.encrypt.asymmetric_encrypt.rsa_pss import sign, verify


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
