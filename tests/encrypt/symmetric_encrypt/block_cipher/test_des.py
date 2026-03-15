# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_des.py
# @time    : 2026/3/15 12:00 Sun
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for DES and 3DES block ciphers

"""
Test suite for DES and 3DES implementations.

Tests include:
- Known test vectors
- Round-trip encryption/decryption
- Comparison with pycryptodome reference implementation
- ECB and CBC modes
- PKCS7 padding
"""

from __future__ import annotations

import pytest
from Crypto.Cipher import DES as CryptoDES
from Crypto.Cipher import DES3 as CryptoDES3
from Crypto.Util.Padding import pad, unpad

from crypt.encrypt.symmetric_encrypt.block_cipher.DES import (
    DES,
    des_encrypt,
    des_decrypt,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.des3 import (
    DES3,
    des3_encrypt,
    des3_decrypt,
)


# Test vectors from NIST SP 800-67
# DES test vectors
DES_TEST_VECTORS = [
    # (key, plaintext, ciphertext) - hex encoded
    (
        "0000000000000000",
        "0000000000000000",
        "8ca64de9c1b123a7",
    ),
    (
        "ffffffffffffffff",
        "ffffffffffffffff",
        "355550b2150e2451",
    ),
    (
        "3000000000000000",
        "1000000000000001",
        "958e6e627a05557b",
    ),
]

# Known answer tests for CBC mode
DES_CBC_TEST_VECTORS = [
    # (key, iv, plaintext, ciphertext) - hex encoded
    (
        "0123456789abcdef",
        "0000000000000000",
        "3736353433323130",
        "3fa40e8a984d4815",
    ),
]


class TestDES:
    """Tests for DES block cipher."""

    def test_des_key_validation(self):
        """Test that DES validates key length."""
        with pytest.raises(ValueError, match="Key must be 8 bytes"):
            DES(b"short")

        with pytest.raises(ValueError, match="Key must be 8 bytes"):
            DES(b"too long key here")

        # Valid key should work
        DES(b"12345678")

    def test_des_iv_validation(self):
        """Test that DES validates IV length."""
        des = DES(b"12345678")

        with pytest.raises(ValueError, match="IV must be 8 bytes"):
            des.encrypt_cbc(b"test", b"short")

        with pytest.raises(ValueError, match="IV must be 8 bytes"):
            des.decrypt_cbc(b"12345678", b"short")

    def test_des_ecb_roundtrip(self):
        """Test DES ECB mode roundtrip encryption/decryption."""
        des = DES(b"12345678")
        plaintext = b"hello wo"

        encrypted = des.encrypt_ecb(plaintext)
        decrypted = des.decrypt_ecb(encrypted)

        assert decrypted == plaintext

    def test_des_cbc_roundtrip(self):
        """Test DES CBC mode roundtrip encryption/decryption."""
        des = DES(b"12345678")
        iv = b"00000000"
        plaintext = b"hello wo"

        encrypted = des.encrypt_cbc(plaintext, iv)
        decrypted = des.decrypt_cbc(encrypted, iv)

        assert decrypted == plaintext

    @pytest.mark.parametrize(
        ("key_hex", "plaintext_hex", "ciphertext_hex"),
        DES_TEST_VECTORS,
    )
    def test_des_known_vectors(self, key_hex, plaintext_hex, ciphertext_hex):
        """Test DES against known test vectors."""
        key = bytes.fromhex(key_hex)
        plaintext = bytes.fromhex(plaintext_hex)
        expected_ciphertext = bytes.fromhex(ciphertext_hex)

        des = DES(key)
        # Note: These vectors are for raw block encryption, not with padding
        # We'll test single block encryption
        from crypt.encrypt.symmetric_encrypt.block_cipher.DES import (
            _bytes_to_int,
            _des_block_encrypt,
            _int_to_bytes,
        )

        block_int = _bytes_to_int(plaintext)
        encrypted_int = _des_block_encrypt(block_int, des.subkeys)
        encrypted = _int_to_bytes(encrypted_int, 8)

        assert encrypted == expected_ciphertext

    def test_des_pkcs7_padding(self):
        """Test PKCS7 padding and unpadding."""
        from crypt.encrypt.symmetric_encrypt.block_cipher.DES import (
            _pkcs7_pad,
            _pkcs7_unpad,
        )

        # Test various lengths
        for length in range(1, 17):
            data = b"A" * length
            padded = _pkcs7_pad(data, 8)
            assert len(padded) % 8 == 0
            unpadded = _pkcs7_unpad(padded)
            assert unpadded == data

        # Test empty data
        padded = _pkcs7_pad(b"", 8)
        assert len(padded) == 8
        assert padded == b"\x08" * 8
        unpadded = _pkcs7_unpad(padded)
        assert unpadded == b""

    def test_des_ciphertext_validation(self):
        """Test that DES validates ciphertext length."""
        des = DES(b"12345678")

        with pytest.raises(ValueError, match="Ciphertext must be multiple of 8 bytes"):
            des.decrypt_ecb(b"short")

        with pytest.raises(ValueError, match="Ciphertext must be multiple of 8 bytes"):
            des.decrypt_cbc(b"short", b"00000000")

    def test_des_convenience_functions(self):
        """Test des_encrypt and des_decrypt convenience functions."""
        key = b"12345678"
        iv = b"00000000"
        plaintext = b"hello world!!!!!"

        # ECB mode
        encrypted = des_encrypt(plaintext, key)
        decrypted = des_decrypt(encrypted, key)
        assert decrypted == plaintext

        # CBC mode
        encrypted = des_encrypt(plaintext, key, iv)
        decrypted = des_decrypt(encrypted, key, iv)
        assert decrypted == plaintext

    def test_des_vs_pycryptodome_ecb(self):
        """Compare DES implementation with pycryptodome."""
        key = b"12345678"
        plaintext = b"hello world!!!!!"  # 16 bytes = 2 blocks

        # Our implementation
        des = DES(key)
        our_encrypted = des.encrypt_ecb(plaintext)
        our_decrypted = des.decrypt_ecb(our_encrypted)

        # PyCryptodome
        crypto_des = CryptoDES.new(key, CryptoDES.MODE_ECB)
        crypto_encrypted = crypto_des.encrypt(pad(plaintext, 8))
        crypto_decrypted = unpad(crypto_des.decrypt(crypto_encrypted), 8)

        assert our_encrypted == crypto_encrypted
        assert our_decrypted == crypto_decrypted

    def test_des_vs_pycryptodome_cbc(self):
        """Compare DES CBC implementation with pycryptodome."""
        key = b"12345678"
        iv = b"00000000"
        plaintext = b"hello world!!!!!"  # 16 bytes = 2 blocks

        # Our implementation
        des = DES(key)
        our_encrypted = des.encrypt_cbc(plaintext, iv)
        our_decrypted = des.decrypt_cbc(our_encrypted, iv)

        # PyCryptodome
        crypto_des = CryptoDES.new(key, CryptoDES.MODE_CBC, iv=iv)
        crypto_encrypted = crypto_des.encrypt(pad(plaintext, 8))
        crypto_decrypted = unpad(crypto_des.decrypt(crypto_encrypted), 8)

        assert our_encrypted == crypto_encrypted
        assert our_decrypted == crypto_decrypted


class TestDES3:
    """Tests for 3DES block cipher."""

    def test_des3_key_validation(self):
        """Test that 3DES validates key length."""
        with pytest.raises(ValueError, match="Key must be 16 or 24 bytes"):
            DES3(b"short")

        with pytest.raises(ValueError, match="Key must be 16 or 24 bytes"):
            DES3(b"eightkey")  # 8 bytes

        with pytest.raises(ValueError, match="Key must be 16 or 24 bytes"):
            DES3(b"this is 25 bytes long!!")  # 25 bytes

        # Valid keys should work
        DES3(b"0123456789abcdef")  # 16 bytes (2-key)
        DES3(b"0123456789abcdef01234567")  # 24 bytes (3-key)

    def test_des3_iv_validation(self):
        """Test that 3DES validates IV length."""
        des3 = DES3(b"0123456789abcdef")

        with pytest.raises(ValueError, match="IV must be 8 bytes"):
            des3.encrypt_cbc(b"test", b"short")

        with pytest.raises(ValueError, match="IV must be 8 bytes"):
            des3.decrypt_cbc(b"12345678", b"short")

    def test_des3_2key_ecb_roundtrip(self):
        """Test 3DES 2-key ECB mode roundtrip."""
        des3 = DES3(b"0123456789abcdef")  # 16 bytes
        plaintext = b"hello wo"

        encrypted = des3.encrypt_ecb(plaintext)
        decrypted = des3.decrypt_ecb(encrypted)

        assert decrypted == plaintext

    def test_des3_2key_cbc_roundtrip(self):
        """Test 3DES 2-key CBC mode roundtrip."""
        des3 = DES3(b"0123456789abcdef")  # 16 bytes
        iv = b"00000000"
        plaintext = b"hello wo"

        encrypted = des3.encrypt_cbc(plaintext, iv)
        decrypted = des3.decrypt_cbc(encrypted, iv)

        assert decrypted == plaintext

    def test_des3_3key_ecb_roundtrip(self):
        """Test 3DES 3-key ECB mode roundtrip."""
        des3 = DES3(b"0123456789abcdef01234567")  # 24 bytes
        plaintext = b"hello wo"

        encrypted = des3.encrypt_ecb(plaintext)
        decrypted = des3.decrypt_ecb(encrypted)

        assert decrypted == plaintext

    def test_des3_3key_cbc_roundtrip(self):
        """Test 3DES 3-key CBC mode roundtrip."""
        des3 = DES3(b"0123456789abcdef01234567")  # 24 bytes
        iv = b"00000000"
        plaintext = b"hello wo"

        encrypted = des3.encrypt_cbc(plaintext, iv)
        decrypted = des3.decrypt_cbc(encrypted, iv)

        assert decrypted == plaintext

    def test_des3_long_plaintext(self):
        """Test 3DES with longer plaintext."""
        des3 = DES3(b"0123456789abcdef")
        iv = b"00000000"
        plaintext = b"This is a longer message that spans multiple blocks!"

        encrypted = des3.encrypt_cbc(plaintext, iv)
        decrypted = des3.decrypt_cbc(encrypted, iv)

        assert decrypted == plaintext

    def test_des3_convenience_functions(self):
        """Test des3_encrypt and des3_decrypt convenience functions."""
        key = b"0123456789abcdef"
        iv = b"00000000"
        plaintext = b"hello world!!!!!"

        # ECB mode
        encrypted = des3_encrypt(plaintext, key)
        decrypted = des3_decrypt(encrypted, key)
        assert decrypted == plaintext

        # CBC mode
        encrypted = des3_encrypt(plaintext, key, iv)
        decrypted = des3_decrypt(encrypted, key, iv)
        assert decrypted == plaintext

    def test_des3_vs_pycryptodome_ecb_2key(self):
        """Compare 3DES 2-key EDE implementation with pycryptodome."""
        key = b"0123456789abcdef"  # 16 bytes
        plaintext = b"hello world!!!!!"  # 16 bytes = 2 blocks

        # Our implementation
        des3 = DES3(key)
        our_encrypted = des3.encrypt_ecb(plaintext)
        our_decrypted = des3.decrypt_ecb(our_encrypted)

        # PyCryptodome
        crypto_des3 = CryptoDES3.new(key, CryptoDES3.MODE_ECB)
        crypto_encrypted = crypto_des3.encrypt(pad(plaintext, 8))
        crypto_decrypted = unpad(crypto_des3.decrypt(crypto_encrypted), 8)

        assert our_encrypted == crypto_encrypted
        assert our_decrypted == crypto_decrypted

    def test_des3_vs_pycryptodome_ecb_3key(self):
        """Compare 3DES 3-key EDE implementation with pycryptodome."""
        key = b"0123456789abcdef01234567"  # 24 bytes
        plaintext = b"hello world!!!!!"  # 16 bytes = 2 blocks

        # Our implementation
        des3 = DES3(key)
        our_encrypted = des3.encrypt_ecb(plaintext)
        our_decrypted = des3.decrypt_ecb(our_encrypted)

        # PyCryptodome
        crypto_des3 = CryptoDES3.new(key, CryptoDES3.MODE_ECB)
        crypto_encrypted = crypto_des3.encrypt(pad(plaintext, 8))
        crypto_decrypted = unpad(crypto_des3.decrypt(crypto_encrypted), 8)

        assert our_encrypted == crypto_encrypted
        assert our_decrypted == crypto_decrypted

    def test_des3_vs_pycryptodome_cbc_2key(self):
        """Compare 3DES 2-key CBC implementation with pycryptodome."""
        key = b"0123456789abcdef"  # 16 bytes
        iv = b"00000000"
        plaintext = b"hello world!!!!!"  # 16 bytes = 2 blocks

        # Our implementation
        des3 = DES3(key)
        our_encrypted = des3.encrypt_cbc(plaintext, iv)
        our_decrypted = des3.decrypt_cbc(our_encrypted, iv)

        # PyCryptodome
        crypto_des3 = CryptoDES3.new(key, CryptoDES3.MODE_CBC, iv=iv)
        crypto_encrypted = crypto_des3.encrypt(pad(plaintext, 8))
        crypto_decrypted = unpad(crypto_des3.decrypt(crypto_encrypted), 8)

        assert our_encrypted == crypto_encrypted
        assert our_decrypted == crypto_decrypted

    def test_des3_vs_pycryptodome_cbc_3key(self):
        """Compare 3DES 3-key CBC implementation with pycryptodome."""
        key = b"0123456789abcdef01234567"  # 24 bytes
        iv = b"00000000"
        plaintext = b"hello world!!!!!"  # 16 bytes = 2 blocks

        # Our implementation
        des3 = DES3(key)
        our_encrypted = des3.encrypt_cbc(plaintext, iv)
        our_decrypted = des3.decrypt_cbc(our_encrypted, iv)

        # PyCryptodome
        crypto_des3 = CryptoDES3.new(key, CryptoDES3.MODE_CBC, iv=iv)
        crypto_encrypted = crypto_des3.encrypt(pad(plaintext, 8))
        crypto_decrypted = unpad(crypto_des3.decrypt(crypto_encrypted), 8)

        assert our_encrypted == crypto_encrypted
        assert our_decrypted == crypto_decrypted

    def test_des3_ciphertext_validation(self):
        """Test that 3DES validates ciphertext length."""
        des3 = DES3(b"0123456789abcdef")

        with pytest.raises(ValueError, match="Ciphertext must be multiple of 8 bytes"):
            des3.decrypt_ecb(b"short")

        with pytest.raises(ValueError, match="Ciphertext must be multiple of 8 bytes"):
            des3.decrypt_cbc(b"short", b"00000000")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
