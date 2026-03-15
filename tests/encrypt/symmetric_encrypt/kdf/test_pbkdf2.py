# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_pbkdf2.py
# @time    : 2026/03/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for PBKDF2 Key Derivation Function
"""
Comprehensive tests for PBKDF2 implementation.

Tests compare against hashlib.pbkdf2_hmac() reference implementation
and include RFC 6070 test vectors.
"""

import hashlib

import pytest

from crypt.encrypt.symmetric_encrypt.kdf.pbkdf2 import (
    pbkdf2,
    pbkdf2_sha1,
    pbkdf2_sha256,
    pbkdf2_sha512,
)


class TestPBKDF2:
    """Test cases for PBKDF2 key derivation function."""

    # ==========================================================================
    # RFC 6070 Test Vectors
    # ==========================================================================

    @pytest.mark.parametrize(
        ("password", "salt", "iterations", "dklen", "hash_name", "expected"),
        [
            # RFC 6070 Test Vector 1: PBKDF2 HMAC-SHA1, "password", "salt", 1 iteration, 20 bytes
            (
                b"password",
                b"salt",
                1,
                20,
                "sha1",
                "0c60c80f961f0e71f3a9b524af6012062fe037a6",
            ),
            # RFC 6070 Test Vector 2: PBKDF2 HMAC-SHA1, "password", "salt", 2 iterations, 20 bytes
            (
                b"password",
                b"salt",
                2,
                20,
                "sha1",
                "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            ),
            # RFC 6070 Test Vector 3: PBKDF2 HMAC-SHA1, "password", "salt", 4096 iterations, 20 bytes
            (
                b"password",
                b"salt",
                4096,
                20,
                "sha1",
                "4b007901b765489abead49d926f721d065a429c1",
            ),
            # RFC 6070 Test Vector 4: PBKDF2 HMAC-SHA256, "password", "salt", 1 iteration, 32 bytes
            (
                b"password",
                b"salt",
                1,
                32,
                "sha256",
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
        ],
    )
    def test_rfc6070_vectors(self, password, salt, iterations, dklen, hash_name, expected):
        """Test against RFC 6070 test vectors."""
        result = pbkdf2(password, salt, iterations, dklen, hash_name)
        assert result.hex() == expected, (
            f"RFC 6070 test failed. Expected: {expected}, Got: {result.hex()}"
        )

    # ==========================================================================
    # Comparison with hashlib reference implementation
    # ==========================================================================

    @pytest.mark.parametrize(
        ("password", "salt", "iterations", "dklen", "hash_name"),
        [
            (b"password", b"salt", 1, 20, "sha1"),
            (b"password", b"salt", 1000, 32, "sha256"),
            (b"password", b"salt", 100000, 64, "sha512"),
            (b"secret", b"random_salt", 5000, 16, "sha1"),
            (b"my_password", b"unique_salt_value", 10000, 48, "sha256"),
            (b"", b"salt", 1000, 32, "sha256"),  # Empty password
            (b"password", b"", 1000, 32, "sha256"),  # Empty salt
            (b"", b"", 1000, 32, "sha256"),  # Both empty
        ],
    )
    def test_against_hashlib(self, password, salt, iterations, dklen, hash_name):
        """Compare custom implementation against hashlib.pbkdf2_hmac()."""
        result_custom = pbkdf2(password, salt, iterations, dklen, hash_name)
        result_hashlib = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)

        assert result_custom == result_hashlib, (
            f"Mismatch with hashlib for {hash_name}, iterations={iterations}, dklen={dklen}"
        )

    # ==========================================================================
    # Different hash functions
    # ==========================================================================

    @pytest.mark.parametrize("hash_name", ["sha1", "sha256", "sha512"])
    def test_different_hash_functions(self, hash_name):
        """Test PBKDF2 with different hash functions."""
        password = b"test_password"
        salt = b"test_salt"
        iterations = 1000
        dklen = 32

        result_custom = pbkdf2(password, salt, iterations, dklen, hash_name)
        result_hashlib = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)

        assert result_custom == result_hashlib

    # ==========================================================================
    # Different iteration counts
    # ==========================================================================

    @pytest.mark.parametrize(
        "iterations",
        [1, 10, 100, 1000, 10000],
    )
    def test_different_iteration_counts(self, iterations):
        """Test PBKDF2 with different iteration counts."""
        password = b"password"
        salt = b"salt"
        dklen = 32
        hash_name = "sha256"

        result_custom = pbkdf2(password, salt, iterations, dklen, hash_name)
        result_hashlib = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)

        assert result_custom == result_hashlib

    def test_minimum_iterations(self):
        """Test with minimum iteration count of 1."""
        result = pbkdf2(b"password", b"salt", 1, 32, "sha256")
        expected = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, 32)
        assert result == expected

    def test_invalid_iterations(self):
        """Test that iterations < 1 raises ValueError."""
        with pytest.raises(ValueError, match="iterations must be at least 1"):
            pbkdf2(b"password", b"salt", 0, 32, "sha256")

        with pytest.raises(ValueError, match="iterations must be at least 1"):
            pbkdf2(b"password", b"salt", -1, 32, "sha256")

    # ==========================================================================
    # Different key lengths (dklen)
    # ==========================================================================

    @pytest.mark.parametrize(
        "dklen",
        [1, 16, 20, 32, 48, 64, 128],
    )
    def test_different_key_lengths(self, dklen):
        """Test PBKDF2 with different derived key lengths."""
        password = b"password"
        salt = b"salt"
        iterations = 1000
        hash_name = "sha256"

        result_custom = pbkdf2(password, salt, iterations, dklen, hash_name)
        result_hashlib = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)

        assert result_custom == result_hashlib
        assert len(result_custom) == dklen

    def test_default_dklen(self):
        """Test that default dklen equals hash digest size."""
        password = b"password"
        salt = b"salt"
        iterations = 1000

        # SHA1 default dklen = 20
        result_sha1 = pbkdf2(password, salt, iterations, hash_name="sha1")
        assert len(result_sha1) == 20

        # SHA256 default dklen = 32
        result_sha256 = pbkdf2(password, salt, iterations, hash_name="sha256")
        assert len(result_sha256) == 32

        # SHA512 default dklen = 64
        result_sha512 = pbkdf2(password, salt, iterations, hash_name="sha512")
        assert len(result_sha512) == 64

    def test_large_dklen(self):
        """Test with dklen larger than hash digest size (requires multiple blocks)."""
        password = b"password"
        salt = b"salt"
        iterations = 1000
        hash_name = "sha256"
        dklen = 100  # Larger than SHA256 digest size (32)

        result_custom = pbkdf2(password, salt, iterations, dklen, hash_name)
        result_hashlib = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)

        assert result_custom == result_hashlib
        assert len(result_custom) == dklen

    # ==========================================================================
    # String and bytes input handling
    # ==========================================================================

    def test_string_password(self):
        """Test that string password is converted to bytes."""
        result = pbkdf2("password", b"salt", 1000, 32, "sha256")
        expected = pbkdf2(b"password", b"salt", 1000, 32, "sha256")
        assert result == expected

    def test_string_salt(self):
        """Test that string salt is converted to bytes."""
        result = pbkdf2(b"password", "salt", 1000, 32, "sha256")
        expected = pbkdf2(b"password", b"salt", 1000, 32, "sha256")
        assert result == expected

    def test_string_password_and_salt(self):
        """Test that both string password and salt are converted to bytes."""
        result = pbkdf2("password", "salt", 1000, 32, "sha256")
        expected = pbkdf2(b"password", b"salt", 1000, 32, "sha256")
        assert result == expected

    def test_bytes_password_and_salt(self):
        """Test that bytes password and salt work correctly."""
        result = pbkdf2(b"password", b"salt", 1000, 32, "sha256")
        expected = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1000, 32)
        assert result == expected

    # ==========================================================================
    # Convenience function tests
    # ==========================================================================

    def test_pbkdf2_sha1_convenience(self):
        """Test pbkdf2_sha1 convenience function."""
        result = pbkdf2_sha1(b"password", b"salt", 1000, 32)
        expected = hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 1000, 32)
        assert result == expected

    def test_pbkdf2_sha256_convenience(self):
        """Test pbkdf2_sha256 convenience function."""
        result = pbkdf2_sha256(b"password", b"salt", 1000, 32)
        expected = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1000, 32)
        assert result == expected

    def test_pbkdf2_sha512_convenience(self):
        """Test pbkdf2_sha512 convenience function."""
        result = pbkdf2_sha512(b"password", b"salt", 1000, 64)
        expected = hashlib.pbkdf2_hmac("sha512", b"password", b"salt", 1000, 64)
        assert result == expected

    # ==========================================================================
    # Edge cases
    # ==========================================================================

    def test_unicode_password(self):
        """Test with unicode password."""
        password = "пароль"  # Russian for "password"
        salt = b"salt"
        iterations = 1000
        dklen = 32
        hash_name = "sha256"

        result = pbkdf2(password, salt, iterations, dklen, hash_name)
        expected = hashlib.pbkdf2_hmac(hash_name, password.encode("utf-8"), salt, iterations, dklen)
        assert result == expected

    def test_unicode_salt(self):
        """Test with unicode salt."""
        password = b"password"
        salt = "соль"  # Russian for "salt"
        iterations = 1000
        dklen = 32
        hash_name = "sha256"

        result = pbkdf2(password, salt, iterations, dklen, hash_name)
        expected = hashlib.pbkdf2_hmac(hash_name, password, salt.encode("utf-8"), iterations, dklen)
        assert result == expected

    def test_long_password(self):
        """Test with a very long password."""
        password = b"A" * 10000
        salt = b"salt"
        iterations = 1000
        dklen = 32
        hash_name = "sha256"

        result = pbkdf2(password, salt, iterations, dklen, hash_name)
        expected = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
        assert result == expected

    def test_long_salt(self):
        """Test with a very long salt."""
        password = b"password"
        salt = b"B" * 10000
        iterations = 1000
        dklen = 32
        hash_name = "sha256"

        result = pbkdf2(password, salt, iterations, dklen, hash_name)
        expected = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
        assert result == expected

    def test_binary_password(self):
        """Test with binary (non-text) password."""
        password = bytes(range(256))
        salt = b"salt"
        iterations = 1000
        dklen = 32
        hash_name = "sha256"

        result = pbkdf2(password, salt, iterations, dklen, hash_name)
        expected = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
        assert result == expected

    def test_binary_salt(self):
        """Test with binary (non-text) salt."""
        password = b"password"
        salt = bytes(range(256))
        iterations = 1000
        dklen = 32
        hash_name = "sha256"

        result = pbkdf2(password, salt, iterations, dklen, hash_name)
        expected = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
        assert result == expected

    # ==========================================================================
    # Error handling
    # ==========================================================================

    def test_unsupported_hash(self):
        """Test that unsupported hash function raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported hash function"):
            pbkdf2(b"password", b"salt", 1000, 32, "md5")

    def test_hash_name_case_insensitive(self):
        """Test that hash name is case insensitive."""
        password = b"password"
        salt = b"salt"
        iterations = 1000
        dklen = 32

        # Test various cases
        result_lower = pbkdf2(password, salt, iterations, dklen, "sha256")
        result_upper = pbkdf2(password, salt, iterations, dklen, "SHA256")
        result_mixed = pbkdf2(password, salt, iterations, dklen, "Sha256")

        assert result_lower == result_upper == result_mixed

    def test_hash_name_with_dash(self):
        """Test that hash name with dash works."""
        password = b"password"
        salt = b"salt"
        iterations = 1000
        dklen = 32

        result = pbkdf2(password, salt, iterations, dklen, "sha-256")
        expected = pbkdf2(password, salt, iterations, dklen, "sha256")

        assert result == expected
