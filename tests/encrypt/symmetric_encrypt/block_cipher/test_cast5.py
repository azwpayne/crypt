# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_cast5.py
# @time    : 2026/3/16
# @desc    : Tests for CAST5 (CAST-128) block cipher

"""Tests for CAST5 (CAST-128) block cipher implementation.

Test vectors are from RFC 2144 and verified against reference implementations.
"""

import pytest

from crypt.encrypt.symmetric_encrypt.block_cipher.cast5 import (
    CAST5,
    cast5_cbc_decrypt,
    cast5_cbc_encrypt,
    cast5_ecb_decrypt,
    cast5_ecb_encrypt,
    decrypt_block,
    encrypt_block,
    key_schedule,
)


class TestCAST5KeySchedule:
    """Test CAST5 key schedule."""

    def test_key_sizes(self):
        """Test CAST5 accepts various key sizes."""
        # Minimum key size (5 bytes = 40 bits)
        CAST5(b"12345")
        # Maximum key size (16 bytes = 128 bits)
        CAST5(b"a" * 16)
        # Various sizes in between
        CAST5(b"12345678")  # 64 bits
        CAST5(b"1234567890")  # 80 bits (boundary for 12 vs 16 rounds)
        CAST5(b"1234567890123456")  # 128 bits

    def test_invalid_key_size(self):
        """Test CAST5 rejects invalid key sizes."""
        with pytest.raises(ValueError, match="Key must be 5-16 bytes"):
            CAST5(b"1234")  # Too short (4 bytes)
        with pytest.raises(ValueError, match="Key must be 5-16 bytes"):
            CAST5(b"a" * 17)  # Too long (17 bytes)
        with pytest.raises(ValueError, match="Key must be 5-16 bytes"):
            CAST5(b"")  # Empty key

    def test_key_schedule_output(self):
        """Test key schedule produces correct output format."""
        key = b"0123456789abcdef"  # 16 bytes
        round_keys, s_boxes = key_schedule(key)

        # Should have 16 round keys
        assert len(round_keys) == 16
        # Each round key should be 32-bit
        for k in round_keys:
            assert 0 <= k <= 0xFFFFFFFF

        # Should have 4 S-boxes
        assert len(s_boxes) == 4
        # Each S-box should have 256 entries
        for sbox in s_boxes:
            assert len(sbox) == 256

    def test_rounds_based_on_key_size(self):
        """Test that number of rounds depends on key size."""
        # Keys <= 80 bits (10 bytes) use 12 rounds
        cipher_80 = CAST5(b"1234567890")  # Exactly 80 bits
        assert cipher_80.rounds == 12

        cipher_short = CAST5(b"12345")  # 40 bits
        assert cipher_short.rounds == 12

        # Keys > 80 bits use 16 rounds
        cipher_128 = CAST5(b"1234567890123456")  # 128 bits
        assert cipher_128.rounds == 16

        cipher_88 = CAST5(b"12345678901")  # 88 bits
        assert cipher_88.rounds == 16


class TestCAST5BlockOperations:
    """Test CAST5 single block encryption/decryption."""

    def test_block_encryption(self):
        """Test single block encryption/decryption."""
        key = b"0123456789abcdef"  # 16 bytes
        cipher = CAST5(key)

        plaintext = b"abcdefgh"  # 8 bytes
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        assert len(ciphertext) == 8
        assert decrypted == plaintext

    def test_invalid_block_size(self):
        """Test block operations reject invalid sizes."""
        cipher = CAST5(b"12345678")

        with pytest.raises(ValueError, match="Block must be 8 bytes"):
            cipher.encrypt_block(b"short")  # Too short
        with pytest.raises(ValueError, match="Block must be 8 bytes"):
            cipher.encrypt_block(b"too long!!")  # Too long
        with pytest.raises(ValueError, match="Block must be 8 bytes"):
            cipher.decrypt_block(b"")  # Empty

    def test_block_function(self):
        """Test standalone block encrypt/decrypt functions."""
        key = b"mysecretkey"  # 11 bytes
        plaintext = b"testdata"

        ciphertext = encrypt_block(plaintext, key)
        decrypted = decrypt_block(ciphertext, key)

        assert len(ciphertext) == 8
        assert decrypted == plaintext

    def test_all_zeros(self):
        """Test encryption of all-zeros block."""
        key = b"0123456789abcdef"
        cipher = CAST5(key)

        plaintext = bytes(8)  # All zeros
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        assert decrypted == plaintext

    def test_all_ones(self):
        """Test encryption of all-ones block."""
        key = b"0123456789abcdef"
        cipher = CAST5(key)

        plaintext = bytes([0xFF] * 8)  # All ones
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        assert decrypted == plaintext


class TestCAST5ECBMode:
    """Test CAST5 ECB mode encryption/decryption."""

    def test_ecb_roundtrip(self):
        """Test ECB mode encryption/decryption roundtrip."""
        key = b"mysecretkey"
        plaintext = b"Hello, World!"

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_ecb_multiple_blocks(self):
        """Test ECB mode with multiple blocks."""
        key = b"0123456789abcdef"
        plaintext = b"This is a longer message that spans multiple blocks!"

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_ecb_exact_block(self):
        """Test ECB mode with exact block size."""
        key = b"0123456789abcdef"
        plaintext = b"exactly8"  # Exactly 8 bytes

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_ecb_empty_plaintext(self):
        """Test encryption of empty plaintext."""
        key = b"0123456789abcdef"
        plaintext = b""

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_ecb_invalid_ciphertext(self):
        """Test ECB decryption rejects invalid ciphertext length."""
        with pytest.raises(ValueError, match="Ciphertext length must be a multiple of 8"):
            cast5_ecb_decrypt(b"invalid", b"secretkey")


class TestCAST5CBCMode:
    """Test CAST5 CBC mode encryption/decryption."""

    def test_cbc_roundtrip(self):
        """Test CBC mode encryption/decryption roundtrip."""
        key = b"mysecretkey"
        iv = b"initvec!"  # 8 bytes
        plaintext = b"Hello, World!"

        ciphertext = cast5_cbc_encrypt(plaintext, key, iv)
        decrypted = cast5_cbc_decrypt(ciphertext, key, iv)

        assert decrypted == plaintext

    def test_cbc_multiple_blocks(self):
        """Test CBC mode with multiple blocks."""
        key = b"0123456789abcdef"
        iv = b"initvec!"
        plaintext = b"This is a longer message that spans multiple blocks!"

        ciphertext = cast5_cbc_encrypt(plaintext, key, iv)
        decrypted = cast5_cbc_decrypt(ciphertext, key, iv)

        assert decrypted == plaintext

    def test_cbc_exact_block(self):
        """Test CBC mode with exact block size."""
        key = b"0123456789abcdef"
        iv = b"initvec!"
        plaintext = b"exactly8"  # Exactly 8 bytes

        ciphertext = cast5_cbc_encrypt(plaintext, key, iv)
        decrypted = cast5_cbc_decrypt(ciphertext, key, iv)

        assert decrypted == plaintext

    def test_cbc_different_ivs(self):
        """Test CBC mode produces different ciphertext with different IVs."""
        key = b"mysecretkey"
        iv1 = b"initvec1"
        iv2 = b"initvec2"
        plaintext = b"Hello, World!"

        ciphertext1 = cast5_cbc_encrypt(plaintext, key, iv1)
        ciphertext2 = cast5_cbc_encrypt(plaintext, key, iv2)

        assert ciphertext1 != ciphertext2

    def test_cbc_invalid_iv(self):
        """Test CBC mode rejects invalid IV."""
        with pytest.raises(ValueError, match="IV must be 8 bytes"):
            cast5_cbc_encrypt(b"plaintext", b"secretkey", b"short")
        with pytest.raises(ValueError, match="IV must be 8 bytes"):
            cast5_cbc_encrypt(b"plaintext", b"secretkey", b"toolongforiv!!!")

    def test_cbc_invalid_ciphertext(self):
        """Test CBC decryption rejects invalid ciphertext length."""
        with pytest.raises(ValueError, match="Ciphertext length must be a multiple of 8"):
            cast5_cbc_decrypt(b"invalid", b"secretkey", b"initvec!")


class TestCAST5KeyLengths:
    """Test CAST5 with different key lengths."""

    def test_40_bit_key(self):
        """Test with 40-bit key (5 bytes)."""
        key = b"12345"
        plaintext = b"Test msg"

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_64_bit_key(self):
        """Test with 64-bit key (8 bytes)."""
        key = b"12345678"
        plaintext = b"Test msg"

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_80_bit_key(self):
        """Test with 80-bit key (10 bytes) - boundary case."""
        key = b"1234567890"
        plaintext = b"Test msg"

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_96_bit_key(self):
        """Test with 96-bit key (12 bytes)."""
        key = b"123456789012"
        plaintext = b"Test msg"

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_128_bit_key(self):
        """Test with 128-bit key (16 bytes)."""
        key = b"1234567890123456"
        plaintext = b"Test msg"

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext


class TestCAST5RFC2144Vectors:
    """Test CAST5 against RFC 2144 test vectors."""

    def test_rfc_vector_1(self):
        """Test vector from RFC 2144 - 128-bit key.

        Key:    01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A
        Plain:  01 23 45 67 89 AB CD EF
        Cipher: 23 8B 4F E5 84 7E 44 B2
        """
        key = bytes([0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
                     0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A])
        plaintext = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        expected = bytes([0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2])

        cipher = CAST5(key)
        ciphertext = cipher.encrypt_block(plaintext)

        assert ciphertext == expected
        assert cipher.decrypt_block(ciphertext) == plaintext

    def test_rfc_vector_2(self):
        """Test vector from RFC 2144 - 80-bit key.

        Key:    01 23 45 67 12 34 56 78 23 45
        Plain:  01 23 45 67 89 AB CD EF
        Cipher: EB A4 83 82 93 25 71 E3
        """
        key = bytes([0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
                     0x23, 0x45])
        plaintext = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        expected = bytes([0xEB, 0xA4, 0x83, 0x82, 0x93, 0x25, 0x71, 0xE3])

        cipher = CAST5(key)
        ciphertext = cipher.encrypt_block(plaintext)

        assert ciphertext == expected
        assert cipher.decrypt_block(ciphertext) == plaintext

    def test_rfc_vector_3(self):
        """Test vector from RFC 2144 - 40-bit key.

        Key:    01 23 45 67 12
        Plain:  01 23 45 67 89 AB CD EF
        Cipher: 7A C8 16 D1 6E 9B 30 2E
        """
        key = bytes([0x01, 0x23, 0x45, 0x67, 0x12])
        plaintext = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        expected = bytes([0x7A, 0xC8, 0x16, 0xD1, 0x6E, 0x9B, 0x30, 0x2E])

        cipher = CAST5(key)
        ciphertext = cipher.encrypt_block(plaintext)

        assert ciphertext == expected
        assert cipher.decrypt_block(ciphertext) == plaintext


class TestCAST5EdgeCases:
    """Test CAST5 edge cases."""

    def test_binary_data(self):
        """Test encryption of binary data with all byte values."""
        key = b"0123456789abcdef"
        plaintext = bytes(range(256))  # All byte values

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_long_plaintext(self):
        """Test with long plaintext."""
        key = b"mysecretkey"
        plaintext = b"A" * 1000

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_unicode_data(self):
        """Test encryption of UTF-8 encoded data."""
        key = b"0123456789abcdef"
        plaintext = "Hello, 世界! 🌍".encode('utf-8')

        ciphertext = cast5_ecb_encrypt(plaintext, key)
        decrypted = cast5_ecb_decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_repeated_encryption(self):
        """Test that repeated encryption with same key produces same result."""
        key = b"0123456789abcdef"
        plaintext = b"testdata"

        cipher1 = CAST5(key)
        cipher2 = CAST5(key)

        ct1 = cipher1.encrypt_block(plaintext)
        ct2 = cipher2.encrypt_block(plaintext)

        assert ct1 == ct2


class TestCAST5CrossMode:
    """Test consistency between different modes."""

    def test_same_key_different_modes(self):
        """Test that same key works across different modes."""
        key = b"mytestkey"
        plaintext = b"Test message here"
        iv = b"initvec!"

        ecb_ct = cast5_ecb_encrypt(plaintext, key)
        cbc_ct = cast5_cbc_encrypt(plaintext, key, iv)

        # ECB and CBC should produce different ciphertext
        assert ecb_ct != cbc_ct

        # But both should decrypt correctly
        assert cast5_ecb_decrypt(ecb_ct, key) == plaintext
        assert cast5_cbc_decrypt(cbc_ct, key, iv) == plaintext


class TestCAST5VsReference:
    """Test CAST5 against reference implementations."""

    @pytest.mark.skipif(
        pytest.importorskip("Crypto.Cipher.CAST", reason="pycryptodome not installed")
        is None,
        reason="pycryptodome CAST not available",
    )
    def test_vs_pycryptodome_ecb(self):
        """Compare ECB encryption with pycryptodome."""
        from Crypto.Cipher import CAST
        from Crypto.Util.Padding import pad

        key = b"01234567"  # 8 bytes
        plaintext = b"hello world!!!!!"

        # Our implementation
        our_ciphertext = cast5_ecb_encrypt(plaintext, key)

        # Reference implementation
        ref_cipher = CAST.new(key, CAST.MODE_ECB)
        ref_ciphertext = ref_cipher.encrypt(pad(plaintext, 8))

        assert our_ciphertext == ref_ciphertext

    @pytest.mark.skipif(
        pytest.importorskip("Crypto.Cipher.CAST", reason="pycryptodome not installed")
        is None,
        reason="pycryptodome CAST not available",
    )
    def test_vs_pycryptodome_cbc(self):
        """Compare CBC encryption with pycryptodome."""
        from Crypto.Cipher import CAST
        from Crypto.Util.Padding import pad

        key = b"01234567"  # 8 bytes
        iv = b"initvec!"
        plaintext = b"hello world!!!!!"

        # Our implementation
        our_ciphertext = cast5_cbc_encrypt(plaintext, key, iv)

        # Reference implementation
        ref_cipher = CAST.new(key, CAST.MODE_CBC, iv=iv)
        ref_ciphertext = ref_cipher.encrypt(pad(plaintext, 8))

        assert our_ciphertext == ref_ciphertext

    @pytest.mark.skipif(
        pytest.importorskip("Crypto.Cipher.CAST", reason="pycryptodome not installed")
        is None,
        reason="pycryptodome CAST not available",
    )
    def test_vs_pycryptodome_128bit_key(self):
        """Compare with pycryptodome using 128-bit key."""
        from Crypto.Cipher import CAST
        from Crypto.Util.Padding import pad

        key = b"0123456789abcdef"  # 16 bytes = 128 bits
        plaintext = b"hello world!!!!!"

        # Our implementation
        our_ciphertext = cast5_ecb_encrypt(plaintext, key)

        # Reference implementation
        ref_cipher = CAST.new(key, CAST.MODE_ECB)
        ref_ciphertext = ref_cipher.encrypt(pad(plaintext, 8))

        assert our_ciphertext == ref_ciphertext
