"""Tests for DSA (Digital Signature Algorithm)."""

from __future__ import annotations

import pytest

from crypt.encrypt.asymmetric_encrypt import dsa


class TestDSA:
    """Test DSA implementation."""

    def test_dsa_key_generation(self) -> None:
        """Test DSA key pair generation."""
        p, q, g = dsa.generate_parameters()
        x, y = dsa.generate_keypair(p, q, g)

        # Verify private key is in valid range
        assert 0 < x < q
        # Verify public key
        assert y == pow(g, x, p)

    def test_dsa_sign_verify(self) -> None:
        """Test DSA signing and verification."""
        p, q, g = dsa.generate_parameters()
        x, y = dsa.generate_keypair(p, q, g)

        message = b"Hello, DSA!"
        signature = dsa.sign(message, p, q, g, x)

        # Verify signature
        assert dsa.verify(message, signature, p, q, g, y)

    def test_dsa_verify_invalid_signature(self) -> None:
        """Test DSA verification with invalid signature."""
        p, q, g = dsa.generate_parameters()
        x, y = dsa.generate_keypair(p, q, g)

        message = b"Hello, DSA!"
        signature = dsa.sign(message, p, q, g, x)

        # Verify with wrong message
        assert not dsa.verify(b"Wrong message", signature, p, q, g, y)

    def test_dsa_sign_verify_empty_message(self) -> None:
        """Test DSA with empty message."""
        p, q, g = dsa.generate_parameters()
        x, y = dsa.generate_keypair(p, q, g)

        message = b""
        signature = dsa.sign(message, p, q, g, x)

        assert dsa.verify(message, signature, p, q, g, y)

    def test_dsa_sign_verify_long_message(self) -> None:
        """Test DSA with long message."""
        p, q, g = dsa.generate_parameters()
        x, y = dsa.generate_keypair(p, q, g)

        message = b"A" * 10000
        signature = dsa.sign(message, p, q, g, x)

        assert dsa.verify(message, signature, p, q, g, y)

    def test_dsa_signature_format(self) -> None:
        """Test DSA signature format."""
        p, q, g = dsa.generate_parameters()
        x, y = dsa.generate_keypair(p, q, g)

        message = b"Test message"
        r, s = dsa.sign(message, p, q, g, x)

        # Signature components should be integers in valid range
        assert isinstance(r, int)
        assert isinstance(s, int)
        assert 0 < r < q
        assert 0 < s < q
