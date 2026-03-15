# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_scrypt_argon2.py
# @time    : 2026/03/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Unit tests for Scrypt and Argon2 KDF implementations

import pytest
import hashlib
from src.crypt.encrypt.symmetric_encrypt.kdf.scrypt import scrypt, _salsa20_8_core, _blockmix
from src.crypt.encrypt.symmetric_encrypt.kdf.argon2 import argon2i, argon2, _Argon2Block


class TestScrypt:
    """Test cases for Scrypt KDF."""

    def test_salsa20_8_core(self):
        """Test Salsa20/8 core function."""
        # Test with non-zero input
        input_data = bytes([i % 256 for i in range(64)])
        result = _salsa20_8_core(input_data)
        assert len(result) == 64
        # Result should be different from input
        assert result != input_data

        # Salsa20/8 on all zeros stays zero (by design of XOR/ADD/ROT)
        zero_input = bytes(64)
        zero_result = _salsa20_8_core(zero_input)
        assert len(zero_result) == 64

    def test_blockmix(self):
        """Test BlockMix function."""
        r = 1
        # Use non-zero input for meaningful test
        input_data = bytes([i % 256 for i in range(128)])  # 2*r*64 = 128
        result = _blockmix(input_data, r)
        assert len(result) == len(input_data)

    def test_scrypt_basic(self):
        """Test basic scrypt functionality."""
        # Use very low parameters for fast testing
        result = scrypt(
            password=b"password",
            salt=b"salt",
            n=2,
            r=1,
            p=1,
            dklen=32
        )
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_scrypt_with_strings(self):
        """Test scrypt with string inputs."""
        result = scrypt(
            password="password",
            salt="salt",
            n=2,
            r=1,
            p=1,
            dklen=32
        )
        assert len(result) == 32

    def test_scrypt_deterministic(self):
        """Test that scrypt produces the same output for same inputs."""
        result1 = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
        assert result1 == result2

    def test_scrypt_different_passwords(self):
        """Test that different passwords produce different outputs."""
        result1 = scrypt(b"password1", b"salt", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password2", b"salt", n=2, r=1, p=1, dklen=32)
        assert result1 != result2

    def test_scrypt_different_salts(self):
        """Test that different salts produce different outputs."""
        result1 = scrypt(b"password", b"salt1", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password", b"salt2", n=2, r=1, p=1, dklen=32)
        assert result1 != result2

    def test_scrypt_different_n(self):
        """Test that different N values produce different outputs."""
        result1 = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
        result2 = scrypt(b"password", b"salt", n=4, r=1, p=1, dklen=32)
        assert result1 != result2

    def test_scrypt_invalid_n_not_power_of_2(self):
        """Test that N must be a power of 2."""
        with pytest.raises(ValueError, match="power of 2"):
            scrypt(b"password", b"salt", n=3, r=1, p=1)

    def test_scrypt_invalid_n_too_small(self):
        """Test that N must be greater than 1."""
        with pytest.raises(ValueError, match="power of 2"):
            scrypt(b"password", b"salt", n=1, r=1, p=1)

    def test_scrypt_invalid_r(self):
        """Test that r must be positive."""
        with pytest.raises(ValueError, match="positive"):
            scrypt(b"password", b"salt", n=2, r=0, p=1)

    def test_scrypt_invalid_p(self):
        """Test that p must be positive."""
        with pytest.raises(ValueError, match="positive"):
            scrypt(b"password", b"salt", n=2, r=1, p=0)

    def test_scrypt_compare_with_hashlib(self):
        """Compare with hashlib.scrypt if available."""
        try:
            expected = hashlib.scrypt(
                b"password",
                salt=b"salt",
                n=2,
                r=1,
                p=1,
                dklen=32
            )
            result = scrypt(b"password", b"salt", n=2, r=1, p=1, dklen=32)
            assert result == expected
        except AttributeError:
            pytest.skip("hashlib.scrypt not available")


class TestArgon2:
    """Test cases for Argon2 KDF."""

    def test_argon2_block(self):
        """Test Argon2 block operations."""
        block = _Argon2Block()
        assert len(block.v) == 128

        # Test to_bytes
        data = block.to_bytes()
        assert len(data) == 1024

        # Test copy
        block2 = block.copy()
        assert block2.v == block.v

        # Test xor
        block.v[0] = 1
        block3 = block.xor(block2)
        assert block3.v[0] == 1

    def test_argon2i_basic(self):
        """Test basic argon2i functionality."""
        result = argon2i(
            password=b"password",
            salt=b"somesalt" * 2,  # 16 bytes
            memory_cost=32,  # Very low for testing
            time_cost=1,
            parallelism=1,
            hash_len=32
        )
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_argon2i_with_strings(self):
        """Test argon2i with string inputs."""
        result = argon2i(
            password="password",
            salt="somesalt" * 2,
            memory_cost=32,
            time_cost=1,
            parallelism=1,
            hash_len=32
        )
        assert len(result) == 32

    def test_argon2i_deterministic(self):
        """Test that argon2i produces the same output for same inputs."""
        result1 = argon2i(b"password", b"somesalt12345678", memory_cost=32, time_cost=1, parallelism=1, hash_len=32)
        result2 = argon2i(b"password", b"somesalt12345678", memory_cost=32, time_cost=1, parallelism=1, hash_len=32)
        assert result1 == result2

    def test_argon2i_different_passwords(self):
        """Test that different passwords produce different outputs."""
        result1 = argon2i(b"password1", b"somesalt12345678", memory_cost=32, time_cost=1, parallelism=1, hash_len=32)
        result2 = argon2i(b"password2", b"somesalt12345678", memory_cost=32, time_cost=1, parallelism=1, hash_len=32)
        assert result1 != result2

    def test_argon2i_different_salts(self):
        """Test that different salts produce different outputs."""
        result1 = argon2i(b"password", b"somesalt12345678", memory_cost=32, time_cost=1, parallelism=1, hash_len=32)
        result2 = argon2i(b"password", b"anothersalt87654", memory_cost=32, time_cost=1, parallelism=1, hash_len=32)
        assert result1 != result2

    def test_argon2_convenience_function(self):
        """Test the argon2 convenience function."""
        result = argon2(
            password=b"password",
            salt=b"somesalt12345678",
            time_cost=1,
            memory_cost=32,
            parallelism=1,
            hash_len=32
        )
        assert len(result) == 32

    def test_argon2i_short_salt(self):
        """Test that short salt raises ValueError."""
        with pytest.raises(ValueError, match="at least 8 bytes"):
            argon2i(b"password", b"short", memory_cost=32, time_cost=1, parallelism=1)

    def test_argon2i_invalid_memory_cost(self):
        """Test that memory_cost must be sufficient."""
        with pytest.raises(ValueError, match="at least"):
            argon2i(b"password", b"somesalt12345678", memory_cost=1, time_cost=1, parallelism=4)

    def test_argon2i_invalid_time_cost(self):
        """Test that time_cost must be at least 1."""
        with pytest.raises(ValueError, match="at least 1"):
            argon2i(b"password", b"somesalt12345678", memory_cost=32, time_cost=0, parallelism=1)

    def test_argon2i_invalid_parallelism(self):
        """Test that parallelism must be at least 1."""
        with pytest.raises(ValueError, match="at least 1"):
            argon2i(b"password", b"somesalt12345678", memory_cost=32, time_cost=1, parallelism=0)

    def test_argon2i_with_key(self):
        """Test argon2i with secret key."""
        result = argon2i(
            password=b"password",
            salt=b"somesalt12345678",
            memory_cost=32,
            time_cost=1,
            parallelism=1,
            hash_len=32,
            key=b"secretkey"
        )
        assert len(result) == 32

    def test_argon2i_with_associated_data(self):
        """Test argon2i with associated data."""
        result = argon2i(
            password=b"password",
            salt=b"somesalt12345678",
            memory_cost=32,
            time_cost=1,
            parallelism=1,
            hash_len=32,
            associated_data=b"context"
        )
        assert len(result) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
