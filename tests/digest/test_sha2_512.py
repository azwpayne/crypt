# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_sha2_512.py
# @time    : 2026/3/18
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for SHA-512 family of hash algorithms
import hashlib

import pytest

from tests import BYTE_TEST_CASES


class TestSha2_512:
    """Tests for SHA-512 hash algorithm."""

    @pytest.mark.parametrize(
        ("msg", "expected"),
        [
            # NIST test vectors from FIPS 180-4
            (
                b"",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
            (
                b"abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            ),
        ],
    )
    def test_sha512_nist_vectors(self, msg, expected):
        """Test SHA-512 against NIST test vectors."""
        from crypt.digest.SHA import sha2_512

        result = sha2_512.sha512(msg)
        assert result == expected, f"Expected: {expected}, Got: {result}"

    @pytest.mark.parametrize(
        "msg",
        BYTE_TEST_CASES,
    )
    def test_sha512_vs_hashlib(self, msg):
        """Test SHA-512 implementation against hashlib reference."""
        from crypt.digest.SHA import sha2_512

        result_custom = sha2_512.sha512(msg)
        result_hashlib = hashlib.sha512(msg).hexdigest()

        assert result_custom == result_hashlib, f"Test case failed for msg: {msg}"

    def test_sha512_short_message(self):
        """Test SHA-512 with a short message."""
        from crypt.digest.SHA import sha2_512

        msg = b"hello"
        result = sha2_512.sha512(msg)
        expected = hashlib.sha512(msg).hexdigest()
        assert result == expected

    def test_sha512_long_message(self):
        """Test SHA-512 with a long message (multiple blocks)."""
        from crypt.digest.SHA import sha2_512

        msg = b"a" * 1000
        result = sha2_512.sha512(msg)
        expected = hashlib.sha512(msg).hexdigest()
        assert result == expected

    def test_sha512_binary_data(self):
        """Test SHA-512 with binary data."""
        from crypt.digest.SHA import sha2_512

        msg = bytes(range(256))
        result = sha2_512.sha512(msg)
        expected = hashlib.sha512(msg).hexdigest()
        assert result == expected


class TestSha2_512_224:
    """Tests for SHA-512/224 hash algorithm."""

    @pytest.mark.parametrize(
        ("msg", "expected"),
        [
            # NIST test vectors from FIPS 180-4
            (
                b"",
                "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
            ),
            (
                b"abc",
                "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
                "fc9be3101845460350061160d05d1092d5d2eb72d62efcaa4f453bf7",
            ),
        ],
    )
    def test_sha512_224_nist_vectors(self, msg, expected):
        """Test SHA-512/224 against NIST test vectors."""
        from crypt.digest.SHA import sha2_512_224

        result = sha2_512_224.sha512_224_hex(msg)
        assert result == expected, f"Expected: {expected}, Got: {result}"

    @pytest.mark.parametrize(
        "msg",
        BYTE_TEST_CASES,
    )
    def test_sha512_224_vs_hashlib(self, msg):
        """Test SHA-512/224 implementation against hashlib reference."""
        from crypt.digest.SHA import sha2_512_224

        result_custom = sha2_512_224.sha512_224_hex(msg)
        result_hashlib = hashlib.new("sha512_224", msg).hexdigest()

        assert result_custom == result_hashlib, f"Test case failed for msg: {msg}"

    def test_sha512_224_returns_bytes(self):
        """Test that sha512_224 returns bytes."""
        from crypt.digest.SHA import sha2_512_224

        result = sha2_512_224.sha512_224(b"test")
        assert isinstance(result, bytes)
        assert len(result) == 28  # 224 bits = 28 bytes

    def test_sha512_224_short_message(self):
        """Test SHA-512/224 with a short message."""
        from crypt.digest.SHA import sha2_512_224

        msg = b"hello"
        result = sha2_512_224.sha512_224_hex(msg)
        expected = hashlib.new("sha512_224", msg).hexdigest()
        assert result == expected

    def test_sha512_224_long_message(self):
        """Test SHA-512/224 with a long message (multiple blocks)."""
        from crypt.digest.SHA import sha2_512_224

        msg = b"a" * 1000
        result = sha2_512_224.sha512_224_hex(msg)
        expected = hashlib.new("sha512_224", msg).hexdigest()
        assert result == expected


class TestSha2_512_256:
    """Tests for SHA-512/256 hash algorithm."""

    @pytest.mark.parametrize(
        ("msg", "expected"),
        [
            # NIST test vectors from FIPS 180-4
            (
                b"",
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            ),
            (
                b"abc",
                "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
                "835f9207766637f832cb3022f9d386b8b9426876f398d6b013a4925cc752806d",
            ),
        ],
    )
    def test_sha512_256_nist_vectors(self, msg, expected):
        """Test SHA-512/256 against NIST test vectors."""
        from crypt.digest.SHA import sha2_512_256

        result = sha2_512_256.sha512_256(msg)
        assert result == expected, f"Expected: {expected}, Got: {result}"

    @pytest.mark.parametrize(
        "msg",
        BYTE_TEST_CASES,
    )
    def test_sha512_256_vs_hashlib(self, msg):
        """Test SHA-512/256 implementation against hashlib reference."""
        from crypt.digest.SHA import sha2_512_256

        result_custom = sha2_512_256.sha512_256(msg)
        result_hashlib = hashlib.new("sha512_256", msg).hexdigest()

        assert result_custom == result_hashlib, f"Test case failed for msg: {msg}"

    def test_sha512_256_short_message(self):
        """Test SHA-512/256 with a short message."""
        from crypt.digest.SHA import sha2_512_256

        msg = b"hello"
        result = sha2_512_256.sha512_256(msg)
        expected = hashlib.new("sha512_256", msg).hexdigest()
        assert result == expected

    def test_sha512_256_long_message(self):
        """Test SHA-512/256 with a long message (multiple blocks)."""
        from crypt.digest.SHA import sha2_512_256

        msg = b"a" * 1000
        result = sha2_512_256.sha512_256(msg)
        expected = hashlib.new("sha512_256", msg).hexdigest()
        assert result == expected

    def test_sha512_256_with_string(self):
        """Test SHA-512/256 with string input."""
        from crypt.digest.SHA import sha2_512_256

        msg = "hello world"
        result = sha2_512_256.sha512_256(msg)
        expected = hashlib.new("sha512_256", msg.encode("utf-8")).hexdigest()
        assert result == expected

    def test_sha512_256_binary_data(self):
        """Test SHA-512/256 with binary data."""
        from crypt.digest.SHA import sha2_512_256

        msg = bytes(range(256))
        result = sha2_512_256.sha512_256(msg)
        expected = hashlib.new("sha512_256", msg).hexdigest()
        assert result == expected
