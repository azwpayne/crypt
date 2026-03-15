# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_rail_fence_cipher.py
# @time    : 2026/3/15
# @desc    : Tests for Rail Fence cipher encryption/decryption

import pytest

from crypt.encrypt.symmetric_encrypt.substitution import rail_fence_cipher


class TestRailFenceEncrypt:
    """Test Rail Fence cipher encryption."""

    def test_encrypt_basic_3_rails(self):
        """Test basic encryption with 3 rails."""
        # HELLOWORLD with 3 rails:
        # H . . . O . . . L . .
        # . E . L . W . R . D .
        # . . L . . . O . . . L
        result = rail_fence_cipher.encrypt("HELLOWORLD", 3)
        assert result == "HOLELWRDLO"

    def test_encrypt_2_rails(self):
        """Test encryption with 2 rails."""
        # HELLO with 2 rails:
        # H . L . O
        # . E . L .
        result = rail_fence_cipher.encrypt("HELLO", 2)
        assert result == "HLOEL"

    def test_encrypt_4_rails(self):
        """Test encryption with 4 rails."""
        result = rail_fence_cipher.encrypt("ABCDEFGHIJKLM", 4)
        # A...G...M
        # .B.F.H.L.
        # ..C.E.I.K
        # ...D...J.
        assert result == "AGMBFHLCEIKDJ"

    def test_encrypt_single_rail_raises(self):
        """Test encryption with 1 rail raises error."""
        with pytest.raises(ValueError, match="栅栏"):
            rail_fence_cipher.encrypt("HELLO", 1)

    def test_encrypt_zero_rails_raises(self):
        """Test encryption with 0 rails raises error."""
        with pytest.raises(ValueError, match="栅栏"):
            rail_fence_cipher.encrypt("HELLO", 0)

    def test_encrypt_negative_rails_raises(self):
        """Test encryption with negative rails raises error."""
        with pytest.raises(ValueError, match="栅栏"):
            rail_fence_cipher.encrypt("HELLO", -1)

    def test_encrypt_text_shorter_than_rails(self):
        """Test encryption when text is shorter than rails."""
        result = rail_fence_cipher.encrypt("AB", 5)
        assert result == "AB"

    def test_encrypt_empty_string(self):
        """Test encryption of empty string."""
        assert rail_fence_cipher.encrypt("", 3) == ""

    def test_encrypt_single_char(self):
        """Test encryption of single character."""
        assert rail_fence_cipher.encrypt("A", 3) == "A"

    def test_encrypt_two_chars(self):
        """Test encryption of two characters."""
        assert rail_fence_cipher.encrypt("AB", 3) == "AB"


class TestRailFenceDecrypt:
    """Test Rail Fence cipher decryption."""

    def test_decrypt_basic_3_rails(self):
        """Test basic decryption with 3 rails."""
        result = rail_fence_cipher.decrypt("HOLELWRDLO", 3)
        assert result == "HELLOWORLD"

    def test_decrypt_2_rails(self):
        """Test decryption with 2 rails."""
        result = rail_fence_cipher.decrypt("HLOEL", 2)
        assert result == "HELLO"

    def test_decrypt_4_rails(self):
        """Test decryption with 4 rails."""
        result = rail_fence_cipher.decrypt("AGMBFHLCEIKDJ", 4)
        assert result == "ABCDEFGHIJKLM"

    def test_decrypt_single_rail_raises(self):
        """Test decryption with 1 rail raises error."""
        with pytest.raises(ValueError, match="栅栏"):
            rail_fence_cipher.decrypt("HELLO", 1)

    def test_decrypt_text_shorter_than_rails(self):
        """Test decryption when text is shorter than rails."""
        result = rail_fence_cipher.decrypt("AB", 5)
        assert result == "AB"

    def test_decrypt_empty_string(self):
        """Test decryption of empty string."""
        assert rail_fence_cipher.decrypt("", 3) == ""


class TestRailFenceRoundtrip:
    """Test encryption/decryption roundtrip."""

    @pytest.mark.parametrize(
        ("text", "rails"),
        [
            ("HELLO", 2),
            ("HELLO WORLD", 3),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4),
            ("SECRET MESSAGE", 5),
            ("A", 3),
            ("AB", 3),
            ("ABC", 3),
            ("", 3),
        ],
    )
    def test_roundtrip(self, text, rails):
        """Test that decrypt(encrypt(text)) == text."""
        encrypted = rail_fence_cipher.encrypt(text, rails)
        decrypted = rail_fence_cipher.decrypt(encrypted, rails)
        assert decrypted == text


class TestRailFenceBruteForce:
    """Test Rail Fence brute force decryption."""

    def test_brute_force_finds_correct_rails(self):
        """Test brute force finds correct rail count."""
        original = "HELLO WORLD"
        rails = 4
        encrypted = rail_fence_cipher.encrypt(original, rails)
        results = rail_fence_cipher.brute_force_decrypt(encrypted, max_rails=10)

        assert rails in results
        assert results[rails] == original

    def test_brute_force_returns_multiple_rails(self):
        """Test brute force returns results for multiple rail counts."""
        results = rail_fence_cipher.brute_force_decrypt("TEST", max_rails=5)

        # Should have results for rails 2, 3, 4 (rails cannot exceed text length)
        assert 2 in results
        assert 3 in results
        assert 4 in results

    def test_brute_force_respects_max_rails(self):
        """Test brute force respects max_rails parameter."""
        results = rail_fence_cipher.brute_force_decrypt("HELLOWORLD", max_rails=3)

        assert 2 in results
        assert 3 in results
        assert 4 not in results

    def test_brute_force_empty_text(self):
        """Test brute force with empty text."""
        results = rail_fence_cipher.brute_force_decrypt("", max_rails=5)

        # Empty text returns empty results (no valid rails for empty text)
        assert results == {}


class TestRailFencePrintFence:
    """Test Rail Fence visualization."""

    def test_print_fence_basic(self):
        """Test basic fence visualization."""
        result = rail_fence_cipher.print_fence("HELLO", 3)
        assert "H" in result
        assert "E" in result
        assert "L" in result
        assert "O" in result

    def test_print_fence_too_long(self):
        """Test print_fence with text too long."""
        result = rail_fence_cipher.print_fence("A" * 100, 3)
        assert "太长" in result

    def test_print_fence_format(self):
        """Test print_fence output format."""
        result = rail_fence_cipher.print_fence("HELLO", 2)
        lines = result.split("\n")
        # Should have 2 lines for 2 rails
        assert len(lines) == 2


class TestRailFenceOffset:
    """Test Rail Fence with offset."""

    def test_encrypt_with_offset(self):
        """Test encryption with offset."""
        # Offset changes starting position
        result1 = rail_fence_cipher.encrypt("HELLO", 3)
        result2 = rail_fence_cipher.encrypt_with_offset("HELLO", 3, 1)

        # Results should be different
        assert result1 != result2

    def test_encrypt_with_offset_zero(self):
        """Test encryption with offset 0 is same as regular."""
        text = "HELLOWORLD"
        result1 = rail_fence_cipher.encrypt(text, 3)
        result2 = rail_fence_cipher.encrypt_with_offset(text, 3, 0)

        assert result1 == result2


class TestRailFenceEdgeCases:
    """Test edge cases."""

    def test_encrypt_unicode(self):
        """Test encryption with unicode characters."""
        result = rail_fence_cipher.encrypt("Héllo", 3)
        # Should preserve unicode characters
        assert "é" in result

    def test_encrypt_with_spaces(self):
        """Test encryption with spaces."""
        result = rail_fence_cipher.encrypt("HELLO WORLD", 3)
        decrypted = rail_fence_cipher.decrypt(result, 3)
        assert decrypted == "HELLO WORLD"

    def test_encrypt_with_special_chars(self):
        """Test encryption with special characters."""
        result = rail_fence_cipher.encrypt("HELLO!@#123", 3)
        decrypted = rail_fence_cipher.decrypt(result, 3)
        assert decrypted == "HELLO!@#123"


class TestRailFenceKnownValues:
    """Test against known values."""

    @pytest.mark.parametrize(
        ("text", "rails", "expected"),
        [
            ("WEAREDISCOVERED", 3, "WECRERDSOEEAIVD"),
            ("DEFENDTHEEASTWALLOFTHECASTLE", 3, "DNETLHSEEDHESWLOTEATEFTAAFCL"),
        ],
    )
    def test_known_values(self, text, rails, expected):
        """Test against known encrypted values."""
        result = rail_fence_cipher.encrypt(text, rails)
        assert result == expected

    @pytest.mark.parametrize(
        ("encrypted", "rails", "expected"),
        [
            ("WECRERDSOEEAIVD", 3, "WEAREDISCOVERED"),
            ("DNETLHSEEDHESWLOTEATEFTAAFCL", 3, "DEFENDTHEEASTWALLOFTHECASTLE"),
        ],
    )
    def test_known_decryptions(self, encrypted, rails, expected):
        """Test against known decrypted values."""
        result = rail_fence_cipher.decrypt(encrypted, rails)
        assert result == expected


class TestRailFenceProperties:
    """Test mathematical properties of Rail Fence cipher."""

    def test_length_preserved(self):
        """Test that encryption preserves length."""
        text = "HELLO WORLD"
        encrypted = rail_fence_cipher.encrypt(text, 3)
        assert len(encrypted) == len(text)

    def test_chars_preserved(self):
        """Test that encryption preserves characters (just reorders)."""
        text = "HELLO"
        encrypted = rail_fence_cipher.encrypt(text, 3)
        assert sorted(encrypted) == sorted(text)

    def test_different_rails_produce_different_results(self):
        """Test that different rail counts produce different results."""
        text = "HELLOWORLD"
        result2 = rail_fence_cipher.encrypt(text, 2)
        result3 = rail_fence_cipher.encrypt(text, 3)
        result4 = rail_fence_cipher.encrypt(text, 4)

        assert result2 != result3
        assert result3 != result4
