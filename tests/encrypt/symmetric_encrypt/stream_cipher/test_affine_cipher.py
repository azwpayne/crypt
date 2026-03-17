"""Tests for Affine cipher implementation."""

from crypt.encrypt.symmetric_encrypt.stream_cipher.affine_cipher import (
    _char_to_num,
    _gcd,
    _mod_inverse,
    _num_to_char,
    brute_force_decrypt,
    decrypt,
    encrypt,
    get_valid_a_values,
)

import pytest


class TestHelperFunctions:
    """Test helper functions."""

    def test_gcd(self):
        """Test GCD calculation."""
        assert _gcd(12, 8) == 4
        assert _gcd(17, 26) == 1
        assert _gcd(5, 26) == 1
        assert _gcd(13, 26) == 13
        assert _gcd(26, 13) == 13

    def test_mod_inverse_exists(self):
        """Test modular inverse when it exists."""
        assert _mod_inverse(5, 26) == 21  # 5*21 = 105 = 1 mod 26
        assert _mod_inverse(3, 26) == 9  # 3*9 = 27 = 1 mod 26
        assert _mod_inverse(1, 26) == 1

    def test_mod_inverse_not_exists(self):
        """Test modular inverse when it doesn't exist."""
        assert _mod_inverse(2, 26) is None
        assert _mod_inverse(13, 26) is None

    def test_char_to_num(self):
        """Test character to number conversion."""
        assert _char_to_num("A") == 0
        assert _char_to_num("Z") == 25
        assert _char_to_num("a") == 0
        assert _char_to_num("z") == 25

    def test_num_to_char(self):
        """Test number to character conversion."""
        assert _num_to_char(0) == "A"
        assert _num_to_char(25) == "Z"
        assert _num_to_char(26) == "A"  # Wrap around


class TestAffineEncrypt:
    """Test Affine encryption."""

    def test_encrypt_basic(self):
        """Test basic encryption."""
        # E(x) = (5x + 8) mod 26
        # H(7) -> (5*7+8)%26 = 43%26 = 17 -> R
        result = encrypt("HELLO", 5, 8)
        assert isinstance(result, str)
        assert len(result) == 5

    def test_encrypt_with_spaces(self):
        """Test encryption preserves non-alpha chars."""
        result = encrypt("HELLO, WORLD!", 5, 8)
        assert "," in result
        assert "!" in result
        assert " " in result

    def test_encrypt_lowercase(self):
        """Test encryption handles lowercase."""
        result = encrypt("hello", 5, 8)
        assert result.isupper()

    def test_encrypt_invalid_key(self):
        """Test that invalid key (not coprime with 26) raises error."""
        with pytest.raises(ValueError, match="互质"):
            encrypt("HELLO", 2, 8)  # 2 and 26 not coprime
        with pytest.raises(ValueError, match="互质"):
            encrypt("HELLO", 13, 8)  # 13 and 26 not coprime

    def test_encrypt_empty(self):
        """Test encryption of empty string."""
        result = encrypt("", 5, 8)
        assert result == ""

    def test_encrypt_no_letters(self):
        """Test encryption of string with no letters."""
        result = encrypt("123!@#", 5, 8)
        assert result == "123!@#"


class TestAffineDecrypt:
    """Test Affine decryption."""

    def test_decrypt_basic(self):
        """Test basic decryption."""
        encrypted = encrypt("HELLO", 5, 8)
        decrypted = decrypt(encrypted, 5, 8)
        assert decrypted == "HELLO"

    def test_decrypt_roundtrip(self):
        """Test encrypt/decrypt roundtrip."""
        original = "ATTACKATDAWN"
        encrypted = encrypt(original, 7, 15)
        decrypted = decrypt(encrypted, 7, 15)
        assert decrypted == original

    def test_decrypt_invalid_key(self):
        """Test that invalid key raises error."""
        with pytest.raises(ValueError, match="逆元"):
            decrypt("HELLO", 2, 8)


class TestBruteForce:
    """Test brute force decryption."""

    def test_brute_force_returns_all_results(self):
        """Test brute force returns all possible keys."""
        encrypted = encrypt("HELLO", 5, 8)
        results = brute_force_decrypt(encrypted)
        # There are 12 valid a values (coprime with 26) and 26 b values
        assert len(results) == 12 * 26

    def test_brute_force_contains_original(self):
        """Test brute force results contain original plaintext."""
        original = "HELLO"
        encrypted = encrypt(original, 5, 8)
        results = brute_force_decrypt(encrypted)
        # Find the correct key
        texts = [r["text"] for r in results]
        assert original in texts


class TestValidAValues:
    """Test getting valid a values."""

    def test_get_valid_a_values(self):
        """Test getting all valid a values."""
        values = get_valid_a_values()
        # Values coprime with 26: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
        expected = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        assert values == expected


class TestAffineEdgeCases:
    """Test edge cases."""

    def test_encrypt_single_letter(self):
        """Test encryption of single letter."""
        result = encrypt("A", 5, 8)
        assert result == "I"  # (5*0+8)%26 = 8 = I

    def test_a_equals_one(self):
        """Test encryption with a=1 (Caesar shift)."""
        result = encrypt("HELLO", 1, 3)
        assert result == "KHOOR"  # Simple Caesar shift by 3

    def test_b_equals_zero(self):
        """Test encryption with b=0."""
        result = encrypt("HELLO", 5, 0)
        decrypted = decrypt(result, 5, 0)
        assert decrypted == "HELLO"

    def test_full_alphabet(self):
        """Test encryption of full alphabet."""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        encrypted = encrypt(alphabet, 5, 8)
        decrypted = decrypt(encrypted, 5, 8)
        assert decrypted == alphabet
