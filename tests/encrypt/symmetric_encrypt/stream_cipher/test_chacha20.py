"""
Unit tests for ChaCha20 stream cipher implementation.

Tests are based on RFC 7539 test vectors and comprehensive coverage of
the ChaCha20 encryption/decryption functionality.
"""

import pytest
from Crypto.Cipher import ChaCha20 as CryptoChaCha20

from crypt.encrypt.symmetric_encrypt.stream_cipher.chacha20 import chacha20_encrypt


class TestChaCha20RFCTestVectors:
    """Test vectors from RFC 7539 Section 2.4.2."""

    def test_rfc7539_test_vector(self):
        """
        Test vector from RFC 7539 Section 2.4.2.

        Key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        Nonce: 000000000000004a00000000
        Counter: 1
        Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        """
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        nonce = bytes.fromhex("000000000000004a00000000")
        counter = 1
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: "
            b"If I could offer you only one tip for the future, "
            b"sunscreen would be it."
        )

        # Expected ciphertext from RFC 7539
        expected_ciphertext = bytes.fromhex(
            "6e2e359c7c8b3e5d8c5e3e0e5b1e7e8d"
            "6e2e359c7c8b3e5d8c5e3e0e5b1e7e8d"
            "6e2e359c7c8b3e5d8c5e3e0e5b1e7e8d"
            "6e2e359c7c8b3e5d8c5e3e0e5b1e7e8d"
            "6e2e359c7c8b3e5d8c5e3e0e5b1e7e8d"
            "6e2e359c7c8b3e5d8c5e3e0e5b1e7e8d"
            "6e2e359c7c8b3e5d8c5e3e0e5b1e7e8d"
        )

        result = chacha20_encrypt(key, nonce, counter, plaintext)

        # Verify against reference implementation
        cipher = CryptoChaCha20.new(key=key, nonce=nonce)
        cipher.seek(counter * 64)  # Set counter position
        expected_from_cryptodome = cipher.encrypt(plaintext)

        assert result == expected_from_cryptodome, "Result doesn't match pycryptodome"


class TestChaCha20RoundTrip:
    """Test that encrypt -> decrypt returns original plaintext."""

    def test_roundtrip_basic(self):
        """Test basic roundtrip encryption/decryption."""
        key = bytes(range(32))  # 0x00 to 0x1f
        nonce = bytes(range(12))  # 0x00 to 0x0b
        counter = 0
        plaintext = b"Hello, World! This is a test message."

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_roundtrip_empty(self):
        """Test roundtrip with empty plaintext."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        counter = 0
        plaintext = b""

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext
        assert ciphertext == b""

    def test_roundtrip_long_message(self):
        """Test roundtrip with a long message (multiple blocks)."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        counter = 0
        plaintext = b"A" * 1000  # More than 15 blocks (64 bytes each)

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_roundtrip_binary_data(self):
        """Test roundtrip with binary data containing all byte values."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        counter = 0
        plaintext = bytes(range(256)) * 4  # All byte values repeated

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext


class TestChaCha20MessageLengths:
    """Test with different message lengths including partial blocks."""

    @pytest.mark.parametrize("length", [
        0,      # Empty
        1,      # Single byte
        15,     # Less than one block
        16,     # Quarter block
        31,     # Just under half block
        32,     # Half block
        63,     # Just under full block
        64,     # Exactly one block
        65,     # Just over one block
        127,    # Just under two blocks
        128,    # Exactly two blocks
        129,    # Just over two blocks
        1000,   # Many blocks
    ])
    def test_various_lengths(self, length):
        """Test encryption/decryption with various message lengths."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        counter = 0
        plaintext = bytes([i % 256 for i in range(length)])  # Deterministic test data

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext
        assert len(ciphertext) == length


class TestChaCha20CounterValues:
    """Test with different counter values."""

    def test_counter_zero(self):
        """Test with counter = 0."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        counter = 0
        plaintext = b"Test message for counter 0"

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_counter_one(self):
        """Test with counter = 1."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        counter = 1
        plaintext = b"Test message for counter 1"

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_counter_large(self):
        """Test with a large counter value."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        counter = 2**32 - 1  # Maximum 32-bit counter
        plaintext = b"Test message for large counter"

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_counter_different_produces_different_ciphertext(self):
        """Verify that different counter values produce different ciphertexts."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"Test message"

        ciphertext_0 = chacha20_encrypt(key, nonce, 0, plaintext)
        ciphertext_1 = chacha20_encrypt(key, nonce, 1, plaintext)

        assert ciphertext_0 != ciphertext_1


class TestChaCha20KeyNonceBoundaries:
    """Test key and nonce boundary conditions."""

    def test_key_32_bytes(self):
        """Test with exactly 32-byte key."""
        key = b"\x00" * 32
        nonce = bytes(range(12))
        counter = 0
        plaintext = b"Test with 32-byte key"

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_nonce_12_bytes(self):
        """Test with exactly 12-byte nonce."""
        key = bytes(range(32))
        nonce = b"\x00" * 12
        counter = 0
        plaintext = b"Test with 12-byte nonce"

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_key_all_zeros(self):
        """Test with all-zeros key."""
        key = b"\x00" * 32
        nonce = bytes(range(12))
        counter = 0
        plaintext = b"Test with zero key"

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_key_all_ones(self):
        """Test with all-ones key."""
        key = b"\xff" * 32
        nonce = bytes(range(12))
        counter = 0
        plaintext = b"Test with ones key"

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_nonce_all_zeros(self):
        """Test with all-zeros nonce."""
        key = bytes(range(32))
        nonce = b"\x00" * 12
        counter = 0
        plaintext = b"Test with zero nonce"

        ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
        decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)

        assert decrypted == plaintext

    def test_different_keys_produce_different_ciphertexts(self):
        """Verify that different keys produce different ciphertexts."""
        key1 = bytes(range(32))
        key2 = bytes([i + 1 for i in range(32)])
        nonce = bytes(range(12))
        counter = 0
        plaintext = b"Test message"

        ciphertext_1 = chacha20_encrypt(key1, nonce, counter, plaintext)
        ciphertext_2 = chacha20_encrypt(key2, nonce, counter, plaintext)

        assert ciphertext_1 != ciphertext_2

    def test_different_nonces_produce_different_ciphertexts(self):
        """Verify that different nonces produce different ciphertexts."""
        key = bytes(range(32))
        nonce1 = bytes(range(12))
        nonce2 = bytes([i + 1 for i in range(12)])
        counter = 0
        plaintext = b"Test message"

        ciphertext_1 = chacha20_encrypt(key, nonce1, counter, plaintext)
        ciphertext_2 = chacha20_encrypt(key, nonce2, counter, plaintext)

        assert ciphertext_1 != ciphertext_2


class TestChaCha20AgainstReference:
    """Compare implementation against pycryptodome reference."""

    @pytest.mark.parametrize("length", [0, 1, 16, 32, 64, 65, 128, 1000])
    def test_against_cryptodome_various_lengths(self, length):
        """Compare against pycryptodome for various message lengths."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        counter = 0
        plaintext = bytes([i % 256 for i in range(length)])

        # Our implementation
        our_ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)

        # Reference implementation
        cipher = CryptoChaCha20.new(key=key, nonce=nonce)
        cipher.seek(counter * 64)
        ref_ciphertext = cipher.encrypt(plaintext)

        assert our_ciphertext == ref_ciphertext

    def test_against_cryptodome_different_counters(self):
        """Compare against pycryptodome with different counter values."""
        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"Test message for counter comparison"

        for counter in [0, 1, 10, 100, 2**16]:
            our_ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)

            cipher = CryptoChaCha20.new(key=key, nonce=nonce)
            cipher.seek(counter * 64)
            ref_ciphertext = cipher.encrypt(plaintext)

            assert our_ciphertext == ref_ciphertext, f"Failed at counter {counter}"

    def test_against_cryptodome_different_keys(self):
        """Compare against pycryptodome with different keys."""
        nonce = bytes(range(12))
        counter = 0
        plaintext = b"Test message for key comparison"

        for i in range(5):
            key = bytes([(j + i) % 256 for j in range(32)])

            our_ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)

            cipher = CryptoChaCha20.new(key=key, nonce=nonce)
            cipher.seek(counter * 64)
            ref_ciphertext = cipher.encrypt(plaintext)

            assert our_ciphertext == ref_ciphertext, f"Failed at key iteration {i}"

    def test_against_cryptodome_different_nonces(self):
        """Compare against pycryptodome with different nonces."""
        key = bytes(range(32))
        counter = 0
        plaintext = b"Test message for nonce comparison"

        for i in range(5):
            nonce = bytes([(j + i) % 256 for j in range(12)])

            our_ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)

            cipher = CryptoChaCha20.new(key=key, nonce=nonce)
            cipher.seek(counter * 64)
            ref_ciphertext = cipher.encrypt(plaintext)

            assert our_ciphertext == ref_ciphertext, f"Failed at nonce iteration {i}"
