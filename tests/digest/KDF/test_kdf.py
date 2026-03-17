"""Tests for Key Derivation Functions (PBKDF2, Scrypt, Argon2)."""

from __future__ import annotations

import hashlib
from crypt.digest.KDF.argon2 import argon2, argon2i
from crypt.digest.KDF.pbkdf2 import pbkdf2, pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha512
from crypt.digest.KDF.scrypt import scrypt

import pytest


class TestPBKDF2:
    """Test PBKDF2 key derivation function."""

    # RFC 6070 test vectors for PBKDF2-HMAC-SHA1
    RFC6070_VECTORS_SHA1 = [
        # (password, salt, iterations, dklen, expected)
        (
            b"password",
            b"salt",
            1,
            20,
            "0c60c80f961f0e71f3a9b524af6012062fe037a6",
        ),
        (
            b"password",
            b"salt",
            2,
            20,
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
        ),
        (
            b"password",
            b"salt",
            4096,
            20,
            "4b007901b765489abead49d926f721d065a429c1",
        ),
        (
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25,
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
        ),
        (b"pass\x00word", b"sa\x00lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"),
    ]

    def test_pbkdf2_basic(self):
        """Test basic PBKDF2 functionality."""
        result = pbkdf2(b"password", b"salt", 1000, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_pbkdf2_default_dklen(self):
        """Test PBKDF2 with default dklen (uses hash length)."""
        result = pbkdf2(b"password", b"salt", 1000)
        # Default SHA256 produces 32 bytes
        assert len(result) == 32

    def test_pbkdf2_string_input(self):
        """Test PBKDF2 accepts string input."""
        result1 = pbkdf2("password", "salt", 1000, 32)
        result2 = pbkdf2(b"password", b"salt", 1000, 32)
        assert result1 == result2

    @pytest.mark.parametrize(
        ("password", "salt", "iterations", "dklen", "expected"),
        RFC6070_VECTORS_SHA1,
    )
    def test_pbkdf2_rfc6070_sha1_vectors(
            self, password, salt, iterations, dklen, expected
    ):
        """Test PBKDF2 against RFC 6070 test vectors (SHA1)."""
        result = pbkdf2(password, salt, iterations, dklen, hash_name="sha1")
        assert result.hex() == expected

    def test_pbkdf2_vs_hashlib_sha256(self):
        """Compare PBKDF2 implementation with hashlib."""
        password = b"test_password"
        salt = b"test_salt"
        iterations = 1000
        dklen = 32

        custom_result = pbkdf2(password, salt, iterations, dklen, hash_name="sha256")
        hashlib_result = hashlib.pbkdf2_hmac("sha256", password, salt, iterations,
                                             dklen)
        assert custom_result == hashlib_result

    def test_pbkdf2_vs_hashlib_sha1(self):
        """Compare PBKDF2-SHA1 with hashlib implementation."""
        password = b"test_password"
        salt = b"test_salt"
        iterations = 1000
        dklen = 20

        custom_result = pbkdf2(password, salt, iterations, dklen, hash_name="sha1")
        hashlib_result = hashlib.pbkdf2_hmac("sha1", password, salt, iterations, dklen)
        assert custom_result == hashlib_result

    def test_pbkdf2_sha1_convenience(self):
        """Test PBKDF2-SHA1 convenience function."""
        result = pbkdf2_sha1(b"password", b"salt", 1000, 20)
        expected = hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 1000, 20)
        assert result == expected

    def test_pbkdf2_sha256_convenience(self):
        """Test PBKDF2-SHA256 convenience function."""
        result = pbkdf2_sha256(b"password", b"salt", 1000, 32)
        expected = pbkdf2(b"password", b"salt", 1000, 32, hash_name="sha256")
        assert result == expected

    def test_pbkdf2_sha512_convenience(self):
        """Test PBKDF2-SHA512 convenience function."""
        result = pbkdf2_sha512(b"password", b"salt", 1000, 64)
        expected = pbkdf2(b"password", b"salt", 1000, 64, hash_name="sha512")
        assert result == expected

    def test_pbkdf2_deterministic(self):
        """Test PBKDF2 is deterministic."""
        result1 = pbkdf2(b"password", b"salt", 1000, 32)
        result2 = pbkdf2(b"password", b"salt", 1000, 32)
        assert result1 == result2

    def test_pbkdf2_different_salts(self):
        """Test different salts produce different keys."""
        result1 = pbkdf2(b"password", b"salt1", 1000, 32)
        result2 = pbkdf2(b"password", b"salt2", 1000, 32)
        assert result1 != result2

    def test_pbkdf2_different_passwords(self):
        """Test different passwords produce different keys."""
        result1 = pbkdf2(b"password1", b"salt", 1000, 32)
        result2 = pbkdf2(b"password2", b"salt", 1000, 32)
        assert result1 != result2

    def test_pbkdf2_invalid_iterations(self):
        """Test PBKDF2 with invalid iterations."""
        with pytest.raises(ValueError, match="iterations must be at least 1"):
            pbkdf2(b"password", b"salt", 0)
        with pytest.raises(ValueError, match="iterations must be at least 1"):
            pbkdf2(b"password", b"salt", -1)

    def test_pbkdf2_unsupported_hash(self):
        """Test PBKDF2 with unsupported hash."""
        with pytest.raises(ValueError, match="Unsupported hash function"):
            pbkdf2(b"password", b"salt", 1000, hash_name="md5")

    def test_pbkdf2_large_dklen(self):
        """Test PBKDF2 with large derived key length."""
        # Should work for reasonable sizes
        result = pbkdf2(b"password", b"salt", 100, dklen=128)
        assert len(result) == 128


class TestScrypt:
    """Test Scrypt key derivation function."""

    def test_scrypt_basic(self):
        """Test basic Scrypt functionality."""
        result = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_scrypt_string_input(self):
        """Test Scrypt accepts string input."""
        result1 = scrypt("password", "salt", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
        assert result1 == result2

    def test_scrypt_deterministic(self):
        """Test Scrypt is deterministic."""
        result1 = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
        assert result1 == result2

    def test_scrypt_different_salts(self):
        """Test different salts produce different keys."""
        result1 = scrypt(b"password", b"salt1", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password", b"salt2", n=2, r=1, p=1, dklen=32)
        assert result1 != result2

    def test_scrypt_different_passwords(self):
        """Test different passwords produce different keys."""
        result1 = scrypt(b"password1", b"salt", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password2", b"salt", n=2, r=1, p=1, dklen=32)
        assert result1 != result2

    def test_scrypt_different_dklen(self):
        """Test different dklen produces different length keys."""
        result1 = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=64)
        assert len(result1) == 32
        assert len(result2) == 64

    def test_scrypt_invalid_n_not_power_of_2(self):
        """Test Scrypt with N not a power of 2."""
        with pytest.raises(ValueError, match="N must be a power of 2"):
            scrypt(b"password", b"salt", n=3, r=1, p=1, dklen=32)

    def test_scrypt_invalid_n_too_small(self):
        """Test Scrypt with N <= 1."""
        with pytest.raises(ValueError, match="N must be a power of 2"):
            scrypt(b"password", b"salt", n=1, r=1, p=1, dklen=32)
        with pytest.raises(ValueError, match="N must be a power of 2"):
            scrypt(b"password", b"salt", n=0, r=1, p=1, dklen=32)

    def test_scrypt_invalid_r(self):
        """Test Scrypt with invalid r."""
        with pytest.raises(ValueError, match="r must be positive"):
            scrypt(b"password", b"salt", n=2, r=0, p=1, dklen=32)
        with pytest.raises(ValueError, match="r must be positive"):
            scrypt(b"password", b"salt", n=2, r=-1, p=1, dklen=32)

    def test_scrypt_invalid_p(self):
        """Test Scrypt with invalid p."""
        with pytest.raises(ValueError, match="p must be positive"):
            scrypt(b"password", b"salt", n=2, r=1, p=0, dklen=32)
        with pytest.raises(ValueError, match="p must be positive"):
            scrypt(b"password", b"salt", n=2, r=1, p=-1, dklen=32)

    def test_scrypt_default_parameters(self):
        """Test Scrypt with default parameters (using small N for speed)."""
        # Note: Default N=2^14 is too slow for tests, use smaller value
        result = scrypt(b"password", b"salt", n=2, r=1, p=1)
        assert isinstance(result, bytes)
        assert len(result) == 64  # Default dklen

    def test_scrypt_various_parameters(self):
        """Test Scrypt with various parameter combinations."""
        test_cases = [
            (2, 1, 1, 32),
            (4, 1, 1, 32),
            (2, 2, 1, 32),
            (2, 1, 2, 32),
            (16, 8, 1, 64),
        ]
        for n, r, p, dklen in test_cases:
            result = scrypt(b"password", b"salt", n=n, r=r, p=p, dklen=dklen)
            assert len(result) == dklen, f"Failed for n={n}, r={r}, p={p}"


class TestArgon2:
    """Test Argon2 key derivation function."""

    def test_argon2i_basic(self):
        """Test basic Argon2i functionality."""
        result = argon2i(
            b"password",
            b"somesalt12345678",  # At least 8 bytes
            memory_cost=64,  # Small for testing
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_argon2i_string_input(self):
        """Test Argon2i accepts string input."""
        result1 = argon2i(
            "password",
            "somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        result2 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        assert result1 == result2

    def test_argon2i_deterministic(self):
        """Test Argon2i is deterministic."""
        result1 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        result2 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        assert result1 == result2

    def test_argon2i_different_salts(self):
        """Test different salts produce different hashes."""
        result1 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        result2 = argon2i(
            b"password",
            b"anothersalt12345",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        assert result1 != result2

    def test_argon2i_different_passwords(self):
        """Test different passwords produce different hashes."""
        result1 = argon2i(
            b"password1",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        result2 = argon2i(
            b"password2",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
        )
        assert result1 != result2

    def test_argon2i_different_hash_len(self):
        """Test different hash_len produces different length hashes."""
        result1 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=16,
        )
        result2 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=64,
        )
        assert len(result1) == 16
        assert len(result2) == 64

    def test_argon2i_invalid_salt_too_short(self):
        """Test Argon2i with salt too short."""
        with pytest.raises(ValueError, match="Salt must be at least 8 bytes"):
            argon2i(
                b"password",
                b"short",  # Less than 8 bytes
                memory_cost=64,
                time_cost=1,
                parallelism=1,
                hash_len=32,
            )

    def test_argon2i_invalid_memory_cost(self):
        """Test Argon2i with invalid memory cost."""
        with pytest.raises(ValueError, match="Memory cost must be at least"):
            argon2i(
                b"password",
                b"somesalt12345678",
                memory_cost=4,  # Too small for parallelism=4
                time_cost=1,
                parallelism=4,
                hash_len=32,
            )

    def test_argon2i_invalid_time_cost(self):
        """Test Argon2i with invalid time cost."""
        with pytest.raises(ValueError, match="Time cost must be at least 1"):
            argon2i(
                b"password",
                b"somesalt12345678",
                memory_cost=64,
                time_cost=0,
                parallelism=1,
                hash_len=32,
            )

    def test_argon2i_invalid_parallelism(self):
        """Test Argon2i with invalid parallelism."""
        with pytest.raises(ValueError, match="Parallelism must be at least 1"):
            argon2i(
                b"password",
                b"somesalt12345678",
                memory_cost=64,
                time_cost=1,
                parallelism=0,
                hash_len=32,
            )

    def test_argon2i_with_key(self):
        """Test Argon2i with optional key."""
        result1 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
            key=b"",
        )
        result2 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
            key=b"secretkey",
        )
        # Different keys should produce different results
        assert result1 != result2

    def test_argon2i_with_associated_data(self):
        """Test Argon2i with associated data."""
        result1 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
            associated_data=b"",
        )
        result2 = argon2i(
            b"password",
            b"somesalt12345678",
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=32,
            associated_data=b"associated_data",
        )
        # Different associated data should produce different results
        assert result1 != result2

    def test_argon2_convenience_function(self):
        """Test argon2 convenience function."""
        result = argon2(
            b"password",
            b"somesalt12345678",
            time_cost=1,
            memory_cost=64,
            parallelism=1,
            hash_len=32,
        )
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_argon2_various_parameters(self):
        """Test Argon2i with various parameter combinations."""
        test_cases = [
            (64, 1, 1, 16),
            (128, 2, 2, 32),
            (256, 3, 4, 64),
        ]
        for memory_cost, time_cost, parallelism, hash_len in test_cases:
            result = argon2i(
                b"password",
                b"somesalt12345678",
                memory_cost=memory_cost,
                time_cost=time_cost,
                parallelism=parallelism,
                hash_len=hash_len,
            )
            assert len(result) == hash_len, (
                f"Failed for memory_cost={memory_cost}, "
                f"time_cost={time_cost}, parallelism={parallelism}"
            )


class TestKDFComparison:
    """Compare different KDF behaviors."""

    def test_different_kdfs_produce_different_results(self):
        """Test that different KDFs produce different keys."""
        password = b"password"
        salt = b"somesalt12345678"

        pbkdf2_result = pbkdf2(password, salt, 100, 32)
        scrypt_result = scrypt(password, salt, n=2, r=1, p=1, dklen=32)
        argon2_result = argon2i(
            password, salt, memory_cost=64, time_cost=1, parallelism=1, hash_len=32
        )

        # All should produce different results
        assert pbkdf2_result != scrypt_result
        assert pbkdf2_result != argon2_result
        assert scrypt_result != argon2_result

    def test_all_kdfs_same_length(self):
        """Test that all KDFs can produce same length keys."""
        password = b"password"
        salt = b"somesalt12345678"
        length = 32

        pbkdf2_result = pbkdf2(password, salt, 100, length)
        scrypt_result = scrypt(password, salt, n=2, r=1, p=1, dklen=length)
        argon2_result = argon2i(
            password,
            salt,
            memory_cost=64,
            time_cost=1,
            parallelism=1,
            hash_len=length,
        )

        assert len(pbkdf2_result) == length
        assert len(scrypt_result) == length
        assert len(argon2_result) == length
