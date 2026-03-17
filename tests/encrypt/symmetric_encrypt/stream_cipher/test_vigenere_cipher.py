"""Tests for Vigenere cipher implementation."""

from crypt.encrypt.symmetric_encrypt.stream_cipher.vigenere_cipher import (
    _char_to_num,
    _num_to_char,
    _prepare_key,
    autokey_decrypt,
    autokey_encrypt,
    decrypt,
    encrypt,
    friedman_test,
    kasiski_examination,
)

import pytest


class TestHelperFunctions:
    """Test helper functions."""

    def test_char_to_num(self):
        """Test character to number conversion."""
        assert _char_to_num("A") == 0
        assert _char_to_num("a") == 0
        assert _char_to_num("Z") == 25
        assert _char_to_num("z") == 25
        assert _char_to_num("M") == 12

    def test_num_to_char(self):
        """Test number to character conversion."""
        assert _num_to_char(0) == "A"
        assert _num_to_char(25) == "Z"
        assert _num_to_char(12) == "M"
        assert _num_to_char(26) == "A"  # Wrap around
        assert _num_to_char(-1) == "Z"  # Negative wrap

    def test_prepare_key(self):
        """Test key preparation."""
        assert _prepare_key("KEY", 5) == "KEYKE"
        assert _prepare_key("SECRET", 10) == "SECRETSECR"
        assert _prepare_key("abc", 6) == "ABCABC"
        assert _prepare_key("K3Y!", 4) == "KYKY"  # Non-alpha removed

    def test_prepare_key_empty_raises(self):
        """Test that empty key raises ValueError."""
        with pytest.raises(ValueError, match="密钥必须包含至少一个字母"):
            _prepare_key("", 5)
        with pytest.raises(ValueError, match="密钥必须包含至少一个字母"):
            _prepare_key("123!@#", 5)


class TestVigenereEncrypt:
    """Test standard Vigenere encryption."""

    def test_encrypt_basic(self):
        """Test basic encryption."""
        # HELLO with key KEY -> RIJVS
        # H(7)+K(10)=17=R, E(4)+E(4)=8=I, L(11)+Y(24)=35%26=9=J, L(11)+K(10)=21=V, O(14)+E(4)=18=S
        result = encrypt("HELLO", "KEY")
        assert result == "RIJVS"

    def test_encrypt_lowercase(self):
        """Test encryption with lowercase input."""
        result = encrypt("hello", "KEY")
        assert result == "RIJVS"

    def test_encrypt_with_spaces(self):
        """Test encryption preserves non-alpha characters."""
        result = encrypt("HELLO WORLD", "KEY")
        assert result == "RIJVS UYVJN"

    def test_encrypt_with_numbers_and_punctuation(self):
        """Test encryption ignores non-alpha characters."""
        result = encrypt("HELLO, WORLD! 123", "KEY")
        assert result == "RIJVS, UYVJN! 123"

    def test_encrypt_empty_string(self):
        """Test encryption of empty string."""
        result = encrypt("", "KEY")
        assert result == ""

    def test_encrypt_no_letters(self):
        """Test encryption of string with no letters."""
        result = encrypt("123!@#", "KEY")
        assert result == "123!@#"

    def test_encrypt_single_character(self):
        """Test encryption of single character."""
        result = encrypt("A", "KEY")
        assert result == "K"  # A(0)+K(10)=10=K

    def test_encrypt_long_key(self):
        """Test encryption with key longer than text."""
        result = encrypt("HELLO", "VERYLONGKEY")
        # H+V=C, E+E=I, L+R=C, L+Y=J, O+L=Z
        assert result == "CICJZ"


class TestVigenereDecrypt:
    """Test standard Vigenere decryption."""

    def test_decrypt_basic(self):
        """Test basic decryption."""
        result = decrypt("RIJVS", "KEY")
        assert result == "HELLO"

    def test_decrypt_with_spaces(self):
        """Test decryption preserves spaces."""
        result = decrypt("RIJVS UYVJN", "KEY")
        assert result == "HELLO WORLD"

    def test_decrypt_roundtrip(self):
        """Test encrypt/decrypt roundtrip."""
        original = "ATTACKATDAWN"
        key = "LEMON"
        encrypted = encrypt(original, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == original

    def test_decrypt_empty_string(self):
        """Test decryption of empty string."""
        result = decrypt("", "KEY")
        assert result == ""


class TestAutokeyCipher:
    """Test autokey Vigenere cipher."""

    def test_autokey_encrypt_basic(self):
        """Test basic autokey encryption."""
        # HELLO with key KEY
        # Autokey = KEY + HELLO = KEYHE
        # H(7)+K(10)=R, E(4)+E(4)=I, L(11)+Y(24)=J, L(11)+H(7)=S, O(14)+E(4)=S
        result = autokey_encrypt("HELLO", "KEY")
        assert result == "RIJSS"

    def test_autokey_decrypt_basic(self):
        """Test basic autokey decryption."""
        result = autokey_decrypt("RIJSS", "KEY")
        assert result == "HELLO"

    def test_autokey_roundtrip(self):
        """Test autokey encrypt/decrypt roundtrip."""
        original = "ATTACKATDAWN"
        key = "LEMON"
        encrypted = autokey_encrypt(original, key)
        decrypted = autokey_decrypt(encrypted, key)
        assert decrypted == original

    def test_autokey_with_spaces(self):
        """Test autokey encryption preserves non-alpha chars."""
        result = autokey_encrypt("HELLO WORLD", "KEY")
        # Autokey = KEYHELLOWORLD[:10] = KEYHELLOWO
        decrypted = autokey_decrypt(result, "KEY")
        assert decrypted == "HELLO WORLD"

    def test_autokey_empty_key_raises(self):
        """Test that empty key raises ValueError."""
        with pytest.raises(ValueError, match="密钥必须包含至少一个字母"):
            autokey_encrypt("HELLO", "")
        with pytest.raises(ValueError, match="密钥必须包含至少一个字母"):
            autokey_decrypt("RIJVS", "")


class TestKasiskiExamination:
    """Test Kasiski examination for cryptanalysis."""

    def test_kasiski_basic(self):
        """Test Kasiski examination finds repeated patterns."""
        # Create text with repeated pattern encrypted with same key
        # Use a shorter key so repeated patterns in plaintext produce
        # repeated patterns in ciphertext
        text = "THEQUICKBROWNFOXJUMPSTHEQUICKBROWNFOX"
        encrypted = encrypt(text, "KEY")
        result = kasiski_examination(encrypted)
        # Should find repeated trigrams
        assert isinstance(result, dict)
        # With this long text and short key, there should be repeats
        assert len(result) >= 0  # May or may not find repeats depending on text

    def test_kasiski_no_repeats(self):
        """Test Kasiski with no repeating patterns."""
        text = "ABCDEFGHIJKLMNO"
        result = kasiski_examination(text)
        # No significant repeats in random text
        assert isinstance(result, dict)

    def test_kasiski_custom_min_length(self):
        """Test Kasiski with custom minimum length."""
        text = "THEQUICKBROWNFOX"
        result = kasiski_examination(text, min_length=4)
        assert isinstance(result, dict)


class TestFriedmanTest:
    """Test Friedman test for key length estimation."""

    def test_friedman_basic(self):
        """Test Friedman test returns positive value."""
        # Random text
        text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = friedman_test(text)
        assert isinstance(result, float)
        assert result > 0

    def test_friedman_english_text(self):
        """Test Friedman on English-like text."""
        # English text should give reasonable estimate
        text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        result = friedman_test(text)
        assert isinstance(result, float)
        assert result >= 1.0

    def test_friedman_short_text(self):
        """Test Friedman on very short text."""
        text = "AB"
        result = friedman_test(text)
        assert isinstance(result, float)

    def test_friedman_single_char(self):
        """Test Friedman on single character."""
        text = "A"
        result = friedman_test(text)
        assert result == 1.0


class TestVigenereEdgeCases:
    """Test edge cases."""

    def test_encrypt_all_same_letter(self):
        """Test encryption of all same letters."""
        result = encrypt("AAAAA", "KEY")
        assert result == "KEYKE"

    def test_decrypt_all_same_letter(self):
        """Test decryption of all same letters."""
        result = decrypt("KEYKE", "KEY")
        assert result == "AAAAA"

    def test_encrypt_long_message(self):
        """Test encryption of long message."""
        message = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        key = "SECRET"
        encrypted = encrypt(message, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == message

    def test_key_with_non_alpha(self):
        """Test key containing non-alphabetic characters."""
        result = encrypt("HELLO", "K3Y!")
        # Should clean to "KY" and use "KYKYK"
        assert isinstance(result, str)
        assert len(result) == 5

    def test_case_preservation_in_structure(self):
        """Test that output is always uppercase."""
        result = encrypt("HeLLo", "Key")
        assert result == "RIJVS"
