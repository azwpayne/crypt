"""Tests for X25519 ECDH key exchange."""

import pytest

from crypt.encrypt.asymmetric_encrypt.x25519 import (
    compute_shared_secret,
    generate_private_key,
    generate_public_key,
)


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
        alice_private = bytes([0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                               0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                               0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                               0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a])

        expected_public = bytes([0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
                                 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
                                 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
                                 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a])

        public_key = generate_public_key(alice_private)
        assert public_key == expected_public

    def test_rfc7748_test_vector_2(self):
        """Test RFC 7748 test vector 2 (Bob's keys)."""
        bob_private = bytes([0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
                             0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
                             0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                             0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb])

        expected_public = bytes([0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
                                 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
                                 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
                                 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f])

        public_key = generate_public_key(bob_private)
        assert public_key == expected_public

    def test_rfc7748_shared_secret(self):
        """Test RFC 7748 shared secret computation."""
        alice_private = bytes([0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                               0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                               0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                               0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a])

        bob_public = bytes([0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
                            0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
                            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
                            0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f])

        expected_shared = bytes([0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                                 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                                 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                                 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42])

        shared = compute_shared_secret(alice_private, bob_public)
        assert shared == expected_shared

    def test_invalid_private_key_length(self):
        """Test that invalid private key length raises error."""
        with pytest.raises(ValueError):
            generate_public_key(b"short")

        with pytest.raises(ValueError):
            generate_public_key(b"x" * 33)

    def test_invalid_public_key_length(self):
        """Test that invalid public key length raises error."""
        private_key = generate_private_key()
        with pytest.raises(ValueError):
            compute_shared_secret(private_key, b"short")

        with pytest.raises(ValueError):
            compute_shared_secret(private_key, b"x" * 33)
