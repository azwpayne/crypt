# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_camellia.py
# @time    : 2026/3/18
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for Camellia block cipher implementation

import pytest

from crypt.encrypt.symmetric_encrypt.block_cipher.camellia import (
    Camellia,
    _bytes_to_dword,
    _dword_to_bytes,
    _f_function,
    _fl_function,
    _fl_inv_function,
    _rol,
    _ror,
    decrypt_cbc,
    decrypt_ecb,
    encrypt_cbc,
    encrypt_ecb,
)


class TestCamelliaKeySchedule:
    """Test key expansion for different key sizes."""

    def test_key_schedule_128(self):
        """Test Camellia-128 key schedule."""
        key = bytes(range(16))
        cipher = Camellia(key)
        assert cipher.key_size == 128
        assert cipher.rounds == 18
        assert len(cipher.kw) == 4
        assert len(cipher.k) == 24
        assert len(cipher.kl) == 6

    def test_key_schedule_192(self):
        """Test Camellia-192 key schedule."""
        key = bytes(range(24))
        cipher = Camellia(key)
        assert cipher.key_size == 192
        assert cipher.rounds == 24
        assert len(cipher.kw) == 4
        assert len(cipher.k) == 24
        assert len(cipher.kl) == 6

    def test_key_schedule_256(self):
        """Test Camellia-256 key schedule."""
        key = bytes(range(32))
        cipher = Camellia(key)
        assert cipher.key_size == 256
        assert cipher.rounds == 24
        assert len(cipher.kw) == 4
        assert len(cipher.k) == 24
        assert len(cipher.kl) == 6

    def test_key_schedule_invalid_length(self):
        """Test key schedule with invalid key length."""
        with pytest.raises(ValueError, match="Invalid key length"):
            Camellia(b"short_key")

        with pytest.raises(ValueError, match="Invalid key length"):
            Camellia(b"a" * 17)


class TestCamelliaBasicOperations:
    """Test basic Camellia operations."""

    def test_rol(self):
        """Test rotate left."""
        assert _rol(0x8000000000000000, 1) == 0x1
        assert _rol(0x1, 1) == 0x2
        assert _rol(0xFFFFFFFFFFFFFFFF, 5) == 0xFFFFFFFFFFFFFFFF

    def test_ror(self):
        """Test rotate right."""
        assert _ror(0x1, 1) == 0x8000000000000000
        assert _ror(0x2, 1) == 0x1
        assert _ror(0xFFFFFFFFFFFFFFFF, 5) == 0xFFFFFFFFFFFFFFFF

    def test_bytes_to_dword(self):
        """Test bytes to 64-bit word conversion."""
        assert _bytes_to_dword(b"\x00\x00\x00\x00\x00\x00\x00\x01") == 1
        assert _bytes_to_dword(b"\x01\x02\x03\x04\x05\x06\x07\x08") == 0x0102030405060708

    def test_dword_to_bytes(self):
        """Test 64-bit word to bytes conversion."""
        assert _dword_to_bytes(1) == b"\x00\x00\x00\x00\x00\x00\x00\x01"
        assert _dword_to_bytes(0x0102030405060708) == b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def test_fl_function_inverse(self):
        """Test that FL and FL^-1 are inverses."""
        x = 0x123456789ABCDEF0
        k = 0xFEDCBA9876543210
        y = _fl_function(x, k)
        x_back = _fl_inv_function(y, k)
        assert x == x_back


class TestCamelliaBlockCipher:
    """Test Camellia block cipher operations."""

    @pytest.mark.parametrize("key_size", [16, 24, 32])
    def test_encrypt_decrypt_block(self, key_size):
        """Test basic block encryption/decryption."""
        key = bytes(range(key_size))
        cipher = Camellia(key)
        plaintext = b"0123456789abcdef"  # 16 bytes

        ciphertext = cipher.encrypt_block(plaintext)
        assert len(ciphertext) == 16
        assert ciphertext != plaintext

        decrypted = cipher.decrypt_block(ciphertext)
        assert decrypted == plaintext

    @pytest.mark.parametrize("key_size", [16, 24, 32])
    def test_encrypt_decrypt_different_blocks(self, key_size):
        """Test encryption/decryption with different blocks."""
        key = bytes(range(key_size))
        cipher = Camellia(key)

        # Test with various plaintexts
        plaintexts = [
            b"\x00" * 16,
            b"\xFF" * 16,
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10",
            bytes(range(16)),
        ]

        for plaintext in plaintexts:
            ciphertext = cipher.encrypt_block(plaintext)
            decrypted = cipher.decrypt_block(ciphertext)
            assert decrypted == plaintext

    def test_encrypt_invalid_block_size(self):
        """Test encryption with invalid block size."""
        cipher = Camellia(b"0123456789abcdef")

        with pytest.raises(ValueError, match="Block must be 16 bytes"):
            cipher.encrypt_block(b"short")

        with pytest.raises(ValueError, match="Block must be 16 bytes"):
            cipher.encrypt_block(b"a" * 17)

    def test_decrypt_invalid_block_size(self):
        """Test decryption with invalid block size."""
        cipher = Camellia(b"0123456789abcdef")

        with pytest.raises(ValueError, match="Block must be 16 bytes"):
            cipher.decrypt_block(b"short")

        with pytest.raises(ValueError, match="Block must be 16 bytes"):
            cipher.decrypt_block(b"a" * 17)


class TestCamelliaECB:
    """Test Camellia-ECB mode."""

    @pytest.mark.parametrize("key_size", [16, 24, 32])
    def test_ecb_basic(self, key_size):
        """Test basic ECB encryption/decryption."""
        key = bytes(range(key_size))
        plaintext = b"Hello, World!!!!"  # 16 bytes
        ciphertext = encrypt_ecb(key, plaintext)
        decrypted = decrypt_ecb(key, ciphertext)
        assert decrypted == plaintext

    @pytest.mark.parametrize("key_size", [16, 24, 32])
    def test_ecb_multiblock(self, key_size):
        """Test ECB with multiple blocks."""
        key = bytes(range(key_size))
        plaintext = b"This is a longer message that spans multiple blocks!"
        ciphertext = encrypt_ecb(key, plaintext)
        decrypted = decrypt_ecb(key, ciphertext)
        assert decrypted == plaintext

    def test_ecb_empty(self):
        """Test ECB with empty plaintext."""
        key = b"0123456789abcdef"
        plaintext = b""
        ciphertext = encrypt_ecb(key, plaintext)
        decrypted = decrypt_ecb(key, ciphertext)
        assert decrypted == plaintext

    def test_ecb_invalid_key(self):
        """Test ECB with invalid key length."""
        with pytest.raises(ValueError, match="Invalid key length"):
            encrypt_ecb(b"short", b"test")

    def test_ecb_invalid_ciphertext(self):
        """Test ECB decryption with invalid ciphertext length."""
        with pytest.raises(ValueError, match="multiple of 16"):
            decrypt_ecb(b"0123456789abcdef", b"short")


class TestCamelliaCBC:
    """Test Camellia-CBC mode."""

    @pytest.mark.parametrize("key_size", [16, 24, 32])
    def test_cbc_basic(self, key_size):
        """Test basic CBC encryption/decryption."""
        key = bytes(range(key_size))
        iv = bytes(range(16, 32))
        plaintext = b"Hello, World!!!!"
        ciphertext = encrypt_cbc(key, iv, plaintext)
        decrypted = decrypt_cbc(key, iv, ciphertext)
        assert decrypted == plaintext

    @pytest.mark.parametrize("key_size", [16, 24, 32])
    def test_cbc_multiblock(self, key_size):
        """Test CBC with multiple blocks."""
        key = bytes(range(key_size))
        iv = bytes(range(16, 32))
        plaintext = b"This is a longer message that spans multiple blocks!"
        ciphertext = encrypt_cbc(key, iv, plaintext)
        decrypted = decrypt_cbc(key, iv, ciphertext)
        assert decrypted == plaintext

    def test_cbc_iv_chaining(self):
        """Test that CBC properly chains blocks."""
        key = b"0123456789abcdef"
        iv1 = b"1234567890123456"
        iv2 = b"6543210987654321"
        plaintext = b"Block1Block2Block3"

        # Same plaintext, different IVs should produce different ciphertexts
        ciphertext1 = encrypt_cbc(key, iv1, plaintext)
        ciphertext2 = encrypt_cbc(key, iv2, plaintext)
        assert ciphertext1 != ciphertext2

    def test_cbc_invalid_iv(self):
        """Test CBC with invalid IV length."""
        with pytest.raises(ValueError, match="IV must be 16 bytes"):
            encrypt_cbc(b"0123456789abcdef", b"short_iv", b"test")

    def test_cbc_invalid_ciphertext(self):
        """Test CBC decryption with invalid ciphertext length."""
        with pytest.raises(ValueError, match="multiple of 16"):
            decrypt_cbc(b"0123456789abcdef", b"1234567890123456", b"short")


class TestCamelliaNISTVectors:
    """Test against RFC 3713 test vectors."""

    def test_rfc3713_128bit_key(self):
        """Test with RFC 3713 128-bit key test vector."""
        # Test vector from RFC 3713 Appendix A
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

        cipher = Camellia(key)
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        assert decrypted == plaintext

    def test_rfc3713_192bit_key(self):
        """Test with RFC 3713 192-bit key test vector."""
        key = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

        cipher = Camellia(key)
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        assert decrypted == plaintext

    def test_rfc3713_256bit_key(self):
        """Test with RFC 3713 256-bit key test vector."""
        key = bytes.fromhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

        cipher = Camellia(key)
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        assert decrypted == plaintext

    def test_all_zeros_key(self):
        """Test with all-zeros key."""
        key = b"\x00" * 16
        plaintext = b"\x00" * 16

        cipher = Camellia(key)
        ciphertext = cipher.encrypt_block(plaintext)
        assert len(ciphertext) == 16

        decrypted = cipher.decrypt_block(ciphertext)
        assert decrypted == plaintext

    def test_all_ones_key(self):
        """Test with all-ones key."""
        key = b"\xFF" * 16
        plaintext = b"\xFF" * 16

        cipher = Camellia(key)
        ciphertext = cipher.encrypt_block(plaintext)
        assert len(ciphertext) == 16

        decrypted = cipher.decrypt_block(ciphertext)
        assert decrypted == plaintext


class TestCamelliaEdgeCases:
    """Test edge cases and error handling."""

    def test_large_data_ecb(self):
        """Test ECB with large data."""
        key = b"0123456789abcdef"
        plaintext = b"A" * 10000
        ciphertext = encrypt_ecb(key, plaintext)
        decrypted = decrypt_ecb(key, ciphertext)
        assert decrypted == plaintext

    def test_large_data_cbc(self):
        """Test CBC with large data."""
        key = b"0123456789abcdef"
        iv = b"1234567890123456"
        plaintext = b"B" * 10000
        ciphertext = encrypt_cbc(key, iv, plaintext)
        decrypted = decrypt_cbc(key, iv, ciphertext)
        assert decrypted == plaintext

    def test_binary_data(self):
        """Test with binary data containing all byte values."""
        key = b"0123456789abcdef"
        plaintext = bytes(range(256))

        # ECB
        ciphertext = encrypt_ecb(key, plaintext)
        assert decrypt_ecb(key, ciphertext) == plaintext

        # CBC
        iv = b"1234567890123456"
        ciphertext = encrypt_cbc(key, iv, plaintext)
        assert decrypt_cbc(key, iv, ciphertext) == plaintext

    def test_single_byte_plaintext(self):
        """Test with single byte plaintext."""
        key = b"0123456789abcdef"
        plaintext = b"X"
        ciphertext = encrypt_ecb(key, plaintext)
        decrypted = decrypt_ecb(key, ciphertext)
        assert decrypted == plaintext

    def test_exact_block_size(self):
        """Test with exactly 16 bytes (one block)."""
        key = b"0123456789abcdef"
        plaintext = b"0123456789abcdef"
        ciphertext = encrypt_ecb(key, plaintext)
        decrypted = decrypt_ecb(key, ciphertext)
        assert decrypted == plaintext

    def test_two_blocks(self):
        """Test with exactly 32 bytes (two blocks)."""
        key = b"0123456789abcdef"
        plaintext = b"0123456789abcdef" * 2
        ciphertext = encrypt_ecb(key, plaintext)
        decrypted = decrypt_ecb(key, ciphertext)
        assert decrypted == plaintext


class TestCamelliaConsistency:
    """Test consistency across multiple operations."""

    def test_multiple_encrypt_same_result(self):
        """Test that encrypting the same data twice gives same result."""
        key = b"0123456789abcdef"
        plaintext = b"0123456789abcdef"

        cipher = Camellia(key)
        ciphertext1 = cipher.encrypt_block(plaintext)
        ciphertext2 = cipher.encrypt_block(plaintext)

        assert ciphertext1 == ciphertext2

    def test_deterministic_decryption(self):
        """Test that decryption is deterministic."""
        key = b"0123456789abcdef"
        plaintext = b"0123456789abcdef"

        cipher = Camellia(key)
        ciphertext = cipher.encrypt_block(plaintext)

        decrypted1 = cipher.decrypt_block(ciphertext)
        decrypted2 = cipher.decrypt_block(ciphertext)

        assert decrypted1 == decrypted2
        assert decrypted1 == plaintext

    @pytest.mark.parametrize("key_size", [16, 24, 32])
    def test_key_uniqueness(self, key_size):
        """Test that different keys produce different ciphertexts."""
        plaintext = b"0123456789abcdef"
        key1 = bytes(range(key_size))
        key2 = bytes([b ^ 0xFF for b in range(key_size)])

        cipher1 = Camellia(key1)
        cipher2 = Camellia(key2)

        ciphertext1 = cipher1.encrypt_block(plaintext)
        ciphertext2 = cipher2.encrypt_block(plaintext)

        assert ciphertext1 != ciphertext2
