# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_simple_substitution.py
# @time    : 2026/3/15
# @desc    : Tests for Simple Substitution cipher encryption/decryption

import pytest

from crypt.encrypt.symmetric_encrypt.substitution import simple_substitution


# A valid 26-letter key for testing
TEST_KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"


class TestSimpleSubstitutionEncrypt:
    """Test Simple Substitution cipher encryption."""

    def test_encrypt_basic(self):
        """Test basic encryption."""
        # A->Q, B->W, C->E, D->R, E->T, F->Y (key is the substitution alphabet)
        # So "ABCDEF" encrypts to "QWERTY"
        result = simple_substitution.encrypt("ABCDEF", TEST_KEY)
        assert result == "QWERTY"

    def test_encrypt_lowercase(self):
        """Test encryption with lowercase input."""
        result = simple_substitution.encrypt("hello", TEST_KEY)
        assert result == "itssg"  # h->I, e->T, l->S, l->S, o->G

    def test_encrypt_mixed_case(self):
        """Test encryption preserves case."""
        result = simple_substitution.encrypt("Hello", TEST_KEY)
        assert result == "Itssg"

    def test_encrypt_preserves_non_alpha(self):
        """Test encryption preserves non-alphabetic characters."""
        result = simple_substitution.encrypt("HELLO, WORLD!", TEST_KEY)
        assert result == "ITSSG, VGKSR!"

    def test_encrypt_empty_string(self):
        """Test encryption of empty string."""
        assert simple_substitution.encrypt("", TEST_KEY) == ""

    def test_encrypt_all_letters(self):
        """Test encryption of all letters."""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = simple_substitution.encrypt(alphabet, TEST_KEY)
        # Each letter should be mapped according to the key
        assert result == TEST_KEY


class TestSimpleSubstitutionDecrypt:
    """Test Simple Substitution cipher decryption."""

    def test_decrypt_basic(self):
        """Test basic decryption."""
        # Q->A, W->B, E->C, R->D, T->E, Y->F in the key
        result = simple_substitution.decrypt("QWERTY", TEST_KEY)
        assert result == "ABCDEF"

    def test_decrypt_lowercase(self):
        """Test decryption with lowercase input."""
        result = simple_substitution.decrypt("itssg", TEST_KEY)
        assert result == "hello"

    def test_decrypt_mixed_case(self):
        """Test decryption preserves case."""
        result = simple_substitution.decrypt("Itssg", TEST_KEY)
        assert result == "Hello"

    def test_decrypt_preserves_non_alpha(self):
        """Test decryption preserves non-alphabetic characters."""
        result = simple_substitution.decrypt("ITSSG, VGKSR!", TEST_KEY)
        assert result == "HELLO, WORLD!"

    def test_decrypt_empty_string(self):
        """Test decryption of empty string."""
        assert simple_substitution.decrypt("", TEST_KEY) == ""


class TestSimpleSubstitutionRoundtrip:
    """Test encryption/decryption roundtrip."""

    @pytest.mark.parametrize(
        ("text"),
        [
            "HELLO",
            "hello",
            "Hello World",
            "ABC123!",
            "",
            "A",
            "THE QUICK BROWN FOX",
            "Attack at dawn!",
        ],
    )
    def test_roundtrip(self, text):
        """Test that decrypt(encrypt(text)) == text."""
        encrypted = simple_substitution.encrypt(text, TEST_KEY)
        decrypted = simple_substitution.decrypt(encrypted, TEST_KEY)
        assert decrypted == text


class TestSimpleSubstitutionInvalidKey:
    """Test handling of invalid keys."""

    def test_encrypt_key_too_short(self):
        """Test encryption with key shorter than 26."""
        with pytest.raises(ValueError, match="长度"):
            simple_substitution.encrypt("HELLO", "TOOLSHORT")

    def test_encrypt_key_too_long(self):
        """Test encryption with key longer than 26."""
        with pytest.raises(ValueError, match="长度"):
            simple_substitution.encrypt("HELLO", "A" * 27)

    def test_encrypt_key_missing_letters(self):
        """Test encryption with key missing some letters."""
        # Key with only 25 unique letters (missing Z), but still 25 chars, so fails length check
        # Actually this test needs a 26-char key with missing letter (duplicates)
        key = "ABCDEFGHIJKLMNOPQRSTUVWXYY"  # Missing Z, has duplicate Y
        with pytest.raises(ValueError, match="字母"):
            simple_substitution.encrypt("HELLO", key)

    def test_encrypt_key_duplicate_letters(self):
        """Test encryption with key containing duplicates."""
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAA"  # All A's
        with pytest.raises(ValueError, match="字母"):
            simple_substitution.encrypt("HELLO", key)

    def test_decrypt_invalid_key(self):
        """Test decryption with invalid key."""
        with pytest.raises(ValueError):
            simple_substitution.decrypt("HELLO", "SHORT")


class TestGenerateRandomKey:
    """Test random key generation."""

    def test_generate_random_key_length(self):
        """Test generated key has correct length."""
        key = simple_substitution.generate_random_key()
        assert len(key) == 26

    def test_generate_random_key_unique(self):
        """Test generated key has all unique letters."""
        key = simple_substitution.generate_random_key()
        assert len(set(key)) == 26

    def test_generate_random_key_uppercase(self):
        """Test generated key is uppercase."""
        key = simple_substitution.generate_random_key()
        assert key.isupper()

    def test_generate_random_key_different(self):
        """Test multiple generated keys are different."""
        key1 = simple_substitution.generate_random_key()
        key2 = simple_substitution.generate_random_key()
        assert key1 != key2

    def test_random_key_is_valid(self):
        """Test that generated key is valid for encryption."""
        key = simple_substitution.generate_random_key()
        # Should not raise
        encrypted = simple_substitution.encrypt("TEST", key)
        decrypted = simple_substitution.decrypt(encrypted, key)
        assert decrypted == "TEST"


class TestGenerateKeyFromKeyword:
    """Test key generation from keyword."""

    def test_generate_key_from_keyword_basic(self):
        """Test basic key generation from keyword."""
        key = simple_substitution.generate_key_from_keyword("KEYWORD")
        # Should start with KEYWORD (without duplicates), then remaining letters
        assert key.startswith("KEYWORD")

    def test_generate_key_from_keyword_length(self):
        """Test generated key has correct length."""
        key = simple_substitution.generate_key_from_keyword("KEYWORD")
        assert len(key) == 26

    def test_generate_key_from_keyword_unique(self):
        """Test generated key has all unique letters."""
        key = simple_substitution.generate_key_from_keyword("KEYWORD")
        assert len(set(key)) == 26

    def test_generate_key_from_keyword_uppercase(self):
        """Test keyword is converted to uppercase."""
        key1 = simple_substitution.generate_key_from_keyword("keyword")
        key2 = simple_substitution.generate_key_from_keyword("KEYWORD")
        assert key1 == key2

    def test_generate_key_from_keyword_with_spaces(self):
        """Test keyword with spaces."""
        key = simple_substitution.generate_key_from_keyword("KEY WORD")
        # Should have K, E, Y, W, O, R, D at start (spaces removed)
        assert key.startswith("KEYWORD")

    def test_generate_key_from_keyword_with_numbers(self):
        """Test keyword with numbers (numbers ignored)."""
        key = simple_substitution.generate_key_from_keyword("K3E5Y")
        assert key.startswith("KEY")

    def test_generate_key_from_keyword_duplicate_letters(self):
        """Test keyword with duplicate letters."""
        key = simple_substitution.generate_key_from_keyword("BANANA")
        # Should be B, A, N, then remaining letters
        assert key.startswith("BAN")
        assert key[3] != "A"  # No more A's

    def test_generated_key_works_for_cipher(self):
        """Test that generated key works for encryption/decryption."""
        key = simple_substitution.generate_key_from_keyword("SECRET")
        text = "HELLO WORLD"
        encrypted = simple_substitution.encrypt(text, key)
        decrypted = simple_substitution.decrypt(encrypted, key)
        assert decrypted == text


class TestFrequencyAnalysis:
    """Test frequency analysis."""

    def test_frequency_analysis_basic(self):
        """Test basic frequency analysis."""
        result = simple_substitution.frequency_analysis("AAA")
        assert result["A"] == 100.0

    def test_frequency_analysis_equal_distribution(self):
        """Test frequency with equal distribution."""
        result = simple_substitution.frequency_analysis("AB")
        assert result["A"] == 50.0
        assert result["B"] == 50.0

    def test_frequency_analysis_empty(self):
        """Test frequency analysis of empty string."""
        result = simple_substitution.frequency_analysis("")
        assert result == {}

    def test_frequency_analysis_no_letters(self):
        """Test frequency analysis of string with no letters."""
        result = simple_substitution.frequency_analysis("123!@#")
        assert result == {}

    def test_frequency_analysis_preserves_case(self):
        """Test frequency analysis is case-insensitive."""
        result1 = simple_substitution.frequency_analysis("AAA")
        result2 = simple_substitution.frequency_analysis("aaa")
        assert result1["A"] == result2["A"]

    def test_frequency_analysis_ignores_non_alpha(self):
        """Test frequency analysis ignores non-alphabetic characters."""
        result = simple_substitution.frequency_analysis("A1B2C3")
        assert result["A"] == pytest.approx(33.33, 0.01)
        assert result["B"] == pytest.approx(33.33, 0.01)
        assert result["C"] == pytest.approx(33.33, 0.01)

    def test_frequency_analysis_result_sorted(self):
        """Test frequency analysis result is sorted by letter."""
        result = simple_substitution.frequency_analysis("ZBA")
        letters = list(result.keys())
        assert letters == sorted(letters)


class TestSimpleSubstitutionEdgeCases:
    """Test edge cases."""

    def test_encrypt_non_alpha_only(self):
        """Test encryption of string with no letters."""
        assert simple_substitution.encrypt("12345!@#$%", TEST_KEY) == "12345!@#$%"

    def test_encrypt_unicode(self):
        """Test encryption with unicode characters."""
        result = simple_substitution.encrypt("Héllo", TEST_KEY)
        # H->I, é preserved, l->S, l->S, o->G
        assert result == "Iéssg"

    def test_decrypt_unicode(self):
        """Test decryption with unicode characters."""
        result = simple_substitution.decrypt("Iéssg", TEST_KEY)
        assert result == "Héllo"


class TestSimpleSubstitutionProperties:
    """Test mathematical properties of substitution cipher."""

    def test_deterministic(self):
        """Test that encryption is deterministic."""
        text = "HELLO"
        result1 = simple_substitution.encrypt(text, TEST_KEY)
        result2 = simple_substitution.encrypt(text, TEST_KEY)
        assert result1 == result2

    def test_injective(self):
        """Test that encryption is injective (different inputs give different outputs)."""
        text1 = "ABC"
        text2 = "DEF"
        result1 = simple_substitution.encrypt(text1, TEST_KEY)
        result2 = simple_substitution.encrypt(text2, TEST_KEY)
        assert result1 != result2

    def test_involution_with_different_keys(self):
        """Test that different keys produce different results."""
        text = "HELLO"
        key1 = "QWERTYUIOPASDFGHJKLZXCVBNM"
        key2 = "ZYXWVUTSRQPONMLKJIHGFEDCBA"

        result1 = simple_substitution.encrypt(text, key1)
        result2 = simple_substitution.encrypt(text, key2)

        assert result1 != result2
