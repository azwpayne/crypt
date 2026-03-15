# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_caesar_cipher.py
# @time    : 2026/3/15
# @desc    : Tests for Caesar cipher encryption/decryption

from crypt.encrypt.symmetric_encrypt.substitution import caesar_cipher

import pytest


class TestCaesarEncrypt:
  """Test Caesar cipher encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption with positive shift."""
    assert caesar_cipher.encrypt("HELLO", 3) == "KHOOR"

  def test_encrypt_lowercase(self):
    """Test encryption with lowercase input."""
    assert caesar_cipher.encrypt("hello", 3) == "khoor"

  def test_encrypt_mixed_case(self):
    """Test encryption with mixed case input."""
    assert caesar_cipher.encrypt("Hello", 3) == "Khoor"
    assert caesar_cipher.encrypt("HeLLo", 3) == "KhOOr"

  def test_encrypt_zero_shift(self):
    """Test encryption with zero shift."""
    assert caesar_cipher.encrypt("HELLO", 0) == "HELLO"

  def test_encrypt_full_rotation(self):
    """Test encryption with full alphabet rotation (26)."""
    assert caesar_cipher.encrypt("HELLO", 26) == "HELLO"

  def test_encrypt_large_shift(self):
    """Test encryption with shift larger than 26."""
    assert caesar_cipher.encrypt("HELLO", 29) == "KHOOR"  # 29 % 26 = 3

  def test_encrypt_negative_shift(self):
    """Test encryption with negative shift."""
    assert caesar_cipher.encrypt("HELLO", -3) == "EBIIL"

  def test_encrypt_with_spaces(self):
    """Test encryption preserves non-alphabetic characters."""
    assert caesar_cipher.encrypt("HELLO WORLD", 3) == "KHOOR ZRUOG"
    assert caesar_cipher.encrypt("HELLO, WORLD!", 3) == "KHOOR, ZRUOG!"

  def test_encrypt_with_numbers(self):
    """Test encryption preserves numbers."""
    assert caesar_cipher.encrypt("ABC123", 1) == "BCD123"

  def test_encrypt_empty_string(self):
    """Test encryption of empty string."""
    assert caesar_cipher.encrypt("", 5) == ""

  def test_encrypt_single_char(self):
    """Test encryption of single character."""
    assert caesar_cipher.encrypt("A", 1) == "B"
    assert caesar_cipher.encrypt("Z", 1) == "A"
    assert caesar_cipher.encrypt("A", -1) == "Z"

  def test_encrypt_wrap_around(self):
    """Test encryption wraps around alphabet."""
    assert caesar_cipher.encrypt("XYZ", 3) == "ABC"

  def test_encrypt_all_letters(self):
    """Test encryption of all letters."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shifted = caesar_cipher.encrypt(alphabet, 1)
    assert shifted == "BCDEFGHIJKLMNOPQRSTUVWXYZA"


class TestCaesarDecrypt:
  """Test Caesar cipher decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    assert caesar_cipher.decrypt("KHOOR", 3) == "HELLO"

  def test_decrypt_lowercase(self):
    """Test decryption with lowercase input."""
    assert caesar_cipher.decrypt("khoor", 3) == "hello"

  def test_decrypt_mixed_case(self):
    """Test decryption with mixed case input."""
    assert caesar_cipher.decrypt("Khoor", 3) == "Hello"

  def test_decrypt_zero_shift(self):
    """Test decryption with zero shift."""
    assert caesar_cipher.decrypt("HELLO", 0) == "HELLO"

  def test_decrypt_with_spaces(self):
    """Test decryption preserves non-alphabetic characters."""
    assert caesar_cipher.decrypt("KHOOR ZRUOG", 3) == "HELLO WORLD"

  def test_decrypt_empty_string(self):
    """Test decryption of empty string."""
    assert caesar_cipher.decrypt("", 5) == ""


class TestCaesarRoundtrip:
  """Test encryption/decryption roundtrip."""

  @pytest.mark.parametrize(
    ("text", "shift"),
    [
      ("HELLO", 3),
      ("hello", 5),
      ("Hello World", 7),
      ("ABC123!@#", 10),
      ("", 5),
      ("A", 13),
      ("The Quick Brown Fox", 25),
    ],
  )
  def test_roundtrip(self, text, shift):
    """Test that decrypt(encrypt(text)) == text."""
    encrypted = caesar_cipher.encrypt(text, shift)
    decrypted = caesar_cipher.decrypt(encrypted, shift)
    assert decrypted == text


class TestCaesarCustomAlphabet:
  """Test Caesar cipher with custom alphabet."""

  def test_encrypt_custom_alphabet(self):
    """Test encryption with custom alphabet."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    result = caesar_cipher.encrypt_with_custom_alphabet("abc", 1, alphabet)
    assert result == "bcd"

  def test_decrypt_custom_alphabet(self):
    """Test decryption with custom alphabet."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    result = caesar_cipher.decrypt_with_custom_alphabet("bcd", 1, alphabet)
    assert result == "abc"

  def test_custom_alphabet_wrap(self):
    """Test custom alphabet wrap-around."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    result = caesar_cipher.encrypt_with_custom_alphabet("9", 1, alphabet)
    assert result == "a"

  def test_custom_alphabet_roundtrip(self):
    """Test custom alphabet roundtrip."""
    alphabet = "ABCDEFGHIJ"
    text = "ABC"
    encrypted = caesar_cipher.encrypt_with_custom_alphabet(text, 2, alphabet)
    decrypted = caesar_cipher.decrypt_with_custom_alphabet(encrypted, 2, alphabet)
    assert decrypted == text

  def test_custom_alphabet_char_not_in_alphabet(self):
    """Test that chars not in alphabet are preserved."""
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    result = caesar_cipher.encrypt_with_custom_alphabet("hello world", 1, alphabet)
    assert result == "ifmmp xpsme"  # space preserved


class TestCaesarBruteForce:
  """Test Caesar cipher brute force decryption."""

  def test_brute_force_decrypt(self):
    """Test brute force returns correct shift."""
    original = "hello"
    encrypted = caesar_cipher.encrypt_with_custom_alphabet(original, 5)
    results = caesar_cipher.brute_force_decrypt(encrypted)

    assert 5 in results
    assert results[5] == original

  def test_brute_force_all_shifts(self):
    """Test brute force returns all 26 shifts."""
    results = caesar_cipher.brute_force_decrypt("test")
    assert len(results) == 26

  def test_brute_force_contains_plaintext(self):
    """Test brute force results contain plaintext somewhere."""
    original = "secret"
    encrypted = caesar_cipher.encrypt_with_custom_alphabet(original, 15)
    results = caesar_cipher.brute_force_decrypt(encrypted)

    # One of the results should be the original
    assert original in results.values()


class TestCaesarEdgeCases:
  """Test edge cases and error handling."""

  def test_encrypt_non_alpha_only(self):
    """Test encryption of string with no letters."""
    assert caesar_cipher.encrypt("12345!@#$%", 5) == "12345!@#$%"

  def test_encrypt_unicode(self):
    """Test encryption with unicode characters."""
    # Unicode characters should be preserved (only ASCII letters are encrypted)
    result = caesar_cipher.encrypt("Héllo", 1)
    assert result == "Iémmp"

  def test_decrypt_unicode(self):
    """Test decryption with unicode characters."""
    result = caesar_cipher.decrypt("Iémmp", 1)
    assert result == "Héllo"

  def test_large_negative_shift(self):
    """Test with large negative shift."""
    # -28 is equivalent to -2 (or +24)
    assert caesar_cipher.encrypt("ABC", -28) == "YZA"

  def test_shift_modulo_26(self):
    """Test that shift is properly modulo 26."""
    # 52 is equivalent to 0
    assert caesar_cipher.encrypt("HELLO", 52) == "HELLO"
    # 53 is equivalent to 1
    assert caesar_cipher.encrypt("HELLO", 53) == "IFMMP"


class TestCaesarKnownValues:
  """Test against known values (ROT13 examples)."""

  def test_rot13_is_caesar_13(self):
    """Verify ROT13 is equivalent to Caesar with shift 13."""
    text = "HELLO"
    caesar_result = caesar_cipher.encrypt(text, 13)

    # ROT13 should be self-inverse
    double_rot13 = caesar_cipher.encrypt(caesar_result, 13)
    assert double_rot13 == text
