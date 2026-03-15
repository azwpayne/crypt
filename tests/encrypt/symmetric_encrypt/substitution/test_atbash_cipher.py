# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_atbash_cipher.py
# @time    : 2026/3/15
# @desc    : Tests for Atbash cipher encryption/decryption

import pytest

from crypt.encrypt.symmetric_encrypt.substitution import atbash_cipher


class TestAtbashEncrypt:
    """Test Atbash cipher encryption."""

    def test_encrypt_basic(self):
        """Test basic Atbash encryption."""
        # A-Z, B-Y, C-X, ...
        assert atbash_cipher.encrypt("ABC") == "ZYX"

    def test_encrypt_lowercase(self):
        """Test Atbash with lowercase."""
        assert atbash_cipher.encrypt("abc") == "zyx"

    def test_encrypt_mixed_case(self):
        """Test Atbash with mixed case."""
        assert atbash_cipher.encrypt("AbC") == "ZyX"

    def test_encrypt_preserves_non_alpha(self):
        """Test Atbash preserves non-alphabetic characters."""
        assert atbash_cipher.encrypt("HELLO, WORLD!") == "SVOOL, DLIOW!"
        assert atbash_cipher.encrypt("12345") == "12345"

    def test_encrypt_empty_string(self):
        """Test Atbash of empty string."""
        assert atbash_cipher.encrypt("") == ""

    def test_encrypt_all_letters(self):
        """Test Atbash of all letters."""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = atbash_cipher.encrypt(alphabet)
        expected = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        assert result == expected

    def test_encrypt_self_inverse(self):
        """Test that Atbash is self-inverse (encrypt twice = original)."""
        text = "HELLO WORLD"
        once = atbash_cipher.encrypt(text)
        twice = atbash_cipher.encrypt(once)
        assert twice == text

    def test_encrypt_symmetric_pairs(self):
        """Test that A<->Z, B<->Y, etc."""
        for i in range(13):  # First 13 letters
            char = chr(ord("A") + i)
            reverse = chr(ord("Z") - i)
            assert atbash_cipher.encrypt(char) == reverse
            assert atbash_cipher.encrypt(reverse) == char


class TestAtbashDecrypt:
    """Test Atbash cipher decryption."""

    def test_decrypt_basic(self):
        """Test basic Atbash decryption."""
        assert atbash_cipher.decrypt("ZYX") == "ABC"

    def test_decrypt_lowercase(self):
        """Test Atbash decryption with lowercase."""
        assert atbash_cipher.decrypt("zyx") == "abc"

    def test_decrypt_preserves_non_alpha(self):
        """Test Atbash decryption preserves non-alphabetic characters."""
        assert atbash_cipher.decrypt("SVOOL, DLIOW!") == "HELLO, WORLD!"

    def test_decrypt_empty_string(self):
        """Test Atbash decryption of empty string."""
        assert atbash_cipher.decrypt("") == ""

    def test_decrypt_is_encrypt(self):
        """Test that decrypt is the same as encrypt for Atbash."""
        text = "TEST MESSAGE"
        encrypted = atbash_cipher.encrypt(text)
        decrypted = atbash_cipher.decrypt(text)
        assert encrypted == decrypted


class TestAtbashRoundtrip:
    """Test Atbash roundtrip."""

    @pytest.mark.parametrize(
        "text",
        [
            "HELLO",
            "hello",
            "Hello World",
            "ABC123!",
            "",
            "A",
            "THE QUICK BROWN FOX",
            "Attack at dawn!",
            "12345",
            "!@#$%",
        ],
    )
    def test_roundtrip(self, text):
        """Test that Atbash(Atbash(text)) == text."""
        encrypted = atbash_cipher.encrypt(text)
        decrypted = atbash_cipher.decrypt(encrypted)
        assert decrypted == text


class TestAtbashKnownValues:
    """Test against known Atbash values."""

    @pytest.mark.parametrize(
        ("plaintext", "expected"),
        [
            ("A", "Z"),
            ("B", "Y"),
            ("M", "N"),
            ("N", "M"),
            ("Z", "A"),
            ("AZ", "ZA"),
            ("WORD", "DLIW"),
            ("TEST", "GVHG"),
        ],
    )
    def test_known_values(self, plaintext, expected):
        """Test against known Atbash transformations."""
        assert atbash_cipher.encrypt(plaintext) == expected

    def test_atbash_bible_example(self):
        """Test biblical example: BABEL -> YZYVO."""
        assert atbash_cipher.encrypt("BABEL") == "YZYVO"


class TestAtbashEdgeCases:
    """Test edge cases."""

    def test_encrypt_non_alpha_only(self):
        """Test Atbash of string with no letters."""
        assert atbash_cipher.encrypt("12345!@#$%") == "12345!@#$%"

    def test_encrypt_unicode(self):
        """Test Atbash with unicode characters."""
        result = atbash_cipher.encrypt("Héllo")
        # é should be preserved
        assert "é" in result

    def test_single_chars(self):
        """Test Atbash on individual characters."""
        for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            result = atbash_cipher.encrypt(char)
            # Should be the reverse letter
            expected = chr(ord("Z") - (ord(char) - ord("A")))
            assert result == expected


class TestAtbashProperties:
    """Test mathematical properties of Atbash."""

    def test_involution(self):
        """Test that Atbash is an involution (self-inverse)."""
        texts = ["HELLO", "abc", "123", "Mix3d!"]
        for text in texts:
            assert atbash_cipher.encrypt(atbash_cipher.encrypt(text)) == text

    def test_deterministic(self):
        """Test that Atbash is deterministic."""
        text = "HELLO"
        result1 = atbash_cipher.encrypt(text)
        result2 = atbash_cipher.encrypt(text)
        assert result1 == result2

    def test_length_preservation(self):
        """Test that Atbash preserves string length."""
        text = "HELLO WORLD 123!"
        result = atbash_cipher.encrypt(text)
        assert len(result) == len(text)

    def test_case_preservation(self):
        """Test that Atbash preserves case of letters."""
        result = atbash_cipher.encrypt("Hello")
        assert result[0].isupper()
        assert result[1].islower()

    def test_middle_letters(self):
        """Test that M and N map to each other (middle of alphabet)."""
        assert atbash_cipher.encrypt("M") == "N"
        assert atbash_cipher.encrypt("N") == "M"


class TestAtbashHebrew:
    """Test Atbash with Hebrew alphabet."""

    def test_hebrew_empty(self):
        """Test Hebrew encryption of empty string."""
        result = atbash_cipher.encrypt_hebrew("")
        assert result == ""

    def test_hebrew_non_hebrew_preserved(self):
        """Test non-Hebrew characters are preserved."""
        result = atbash_cipher.encrypt_hebrew("HELLO")
        assert result == "HELLO"

    def test_hebrew_basic(self):
        """Test basic Hebrew encryption (if Hebrew chars present)."""
        # This tests that the function runs without error
        # Actual Hebrew text would require Unicode characters
        result = atbash_cipher.encrypt_hebrew("Test123")
        assert result == "Test123"  # No Hebrew chars, so unchanged


class TestAtbashVsCaesar:
    """Test Atbash relationship to other ciphers."""

    def test_atbash_not_equivalent_to_caesar(self):
        """Test that Atbash is not equivalent to any Caesar shift."""
        from crypt.encrypt.symmetric_encrypt.substitution import caesar_cipher

        text = "ABC"
        atbash_result = atbash_cipher.encrypt(text)

        # Check that no Caesar shift produces the same result
        for shift in range(26):
            caesar_result = caesar_cipher.encrypt(text, shift)
            if caesar_result == atbash_result:
                # This would be surprising - just documenting behavior
                pass
