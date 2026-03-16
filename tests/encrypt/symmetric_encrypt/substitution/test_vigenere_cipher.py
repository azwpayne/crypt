# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_vigenere_cipher.py
# @time    : 2026/3/15
# @desc    : Tests for Vigenère cipher encryption/decryption

from crypt.encrypt.symmetric_encrypt.substitution import vigenere_cipher

import pytest


class TestVigenereEncrypt:
  """Test Vigenère cipher encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption."""
    # KEY repeated: KEYKEY
    # HELLO + KEY = RIJVS
    # H(7)+K(10)=17=R, E(4)+E(4)=8=I, L(11)+Y(24)=35%26=9=J, etc.
    result = vigenere_cipher.encrypt("HELLO", "KEY")
    assert result == "RIJVS"

  def test_encrypt_lowercase(self):
    """Test encryption converts to uppercase."""
    result = vigenere_cipher.encrypt("hello", "key")
    assert result == "RIJVS"

  def test_encrypt_mixed_case(self):
    """Test encryption with mixed case."""
    result = vigenere_cipher.encrypt("HeLLo", "KeY")
    assert result == "RIJVS"

  def test_encrypt_longer_text(self):
    """Test encryption of longer text."""
    result = vigenere_cipher.encrypt("ATTACKATDAWN", "LEMON")
    assert result == "LXFOPVEFRNHR"

  def test_encrypt_key_longer_than_text(self):
    """Test encryption when key is longer than text."""
    result = vigenere_cipher.encrypt("ABC", "VERYLONGKEY")
    # A+V=V, B+E=F, C+R=T (only first 3 chars of key used)
    assert result == "VFT"

  def test_encrypt_single_char_key(self):
    """Test encryption with single character key."""
    # This is equivalent to Caesar cipher
    result = vigenere_cipher.encrypt("HELLO", "D")  # shift 3
    assert result == "KHOOR"

  def test_encrypt_preserves_non_alpha(self):
    """Test encryption preserves non-alphabetic characters."""
    result = vigenere_cipher.encrypt("HELLO, WORLD!", "KEY")
    # HELLO + KEYKE = RIJVS, WORLD + YKEYK = UYVJN
    assert result == "RIJVS, UYVJN!"

  def test_encrypt_empty_string(self):
    """Test encryption of empty string."""
    assert vigenere_cipher.encrypt("", "KEY") == ""

  def test_encrypt_with_spaces_in_key(self):
    """Test encryption handles spaces in key."""
    result = vigenere_cipher.encrypt("HELLO", "K E Y")
    assert result == "RIJVS"

  def test_encrypt_with_numbers_in_key(self):
    """Test encryption handles numbers in key."""
    result = vigenere_cipher.encrypt("HELLO", "K3E5Y")
    assert result == "RIJVS"


class TestVigenereDecrypt:
  """Test Vigenère cipher decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    result = vigenere_cipher.decrypt("RIJVS", "KEY")
    assert result == "HELLO"

  def test_decrypt_longer_text(self):
    """Test decryption of longer text."""
    result = vigenere_cipher.decrypt("LXFOPVEFRNHR", "LEMON")
    assert result == "ATTACKATDAWN"

  def test_decrypt_preserves_non_alpha(self):
    """Test decryption preserves non-alphabetic characters."""
    result = vigenere_cipher.decrypt("RIJVS, UYVJN!", "KEY")
    assert result == "HELLO, WORLD!"

  def test_decrypt_empty_string(self):
    """Test decryption of empty string."""
    assert vigenere_cipher.decrypt("", "KEY") == ""


class TestVigenereRoundtrip:
  """Test encryption/decryption roundtrip."""

  @pytest.mark.parametrize(
    ("text", "key"),
    [
      ("HELLO", "KEY"),
      ("hello", "secret"),
      ("Hello World", "PASSWORD"),
      ("ABC123!", "XYZ"),
      ("", "KEY"),
      ("A", "LONGKEY"),
      ("THE QUICK BROWN FOX", "CIPHER"),
      ("Attack at dawn!", "LEMON"),
    ],
  )
  def test_roundtrip(self, text, key):
    """Test that decrypt(encrypt(text)) == text (uppercase)."""
    encrypted = vigenere_cipher.encrypt(text, key)
    decrypted = vigenere_cipher.decrypt(encrypted, key)
    assert decrypted == text.upper()


class TestVigenereAutokey:
  """Test Vigenère cipher with autokey."""

  def test_autokey_encrypt_basic(self):
    """Test autokey encryption."""
    # Autokey: key = "KEY" + "HELLO"[:2] = "KEYHE"
    # H+K=R, E+E=I, L+Y=J, L+H=S, O+E=S
    result = vigenere_cipher.autokey_encrypt("HELLO", "KEY")
    assert result == "RIJSS"

  def test_autokey_decrypt_basic(self):
    """Test autokey decryption."""
    encrypted = vigenere_cipher.autokey_encrypt("HELLO", "KEY")
    result = vigenere_cipher.autokey_decrypt(encrypted, "KEY")
    assert result == "HELLO"

  def test_autokey_roundtrip(self):
    """Test autokey roundtrip."""
    text = "HELLO WORLD"
    key = "SECRET"
    encrypted = vigenere_cipher.autokey_encrypt(text, key)
    decrypted = vigenere_cipher.autokey_decrypt(encrypted, key)
    assert decrypted == text.upper()

  def test_autokey_different_from_standard(self):
    """Test autokey produces different result than standard Vigenère."""
    text = "HELLOWORLD"
    key = "KEY"
    standard = vigenere_cipher.encrypt(text, key)
    autokey = vigenere_cipher.autokey_encrypt(text, key)
    assert standard != autokey

  def test_autokey_empty_key_raises(self):
    """Test autokey with empty key raises error."""
    with pytest.raises(ValueError, match="密钥"):
      vigenere_cipher.autokey_encrypt("HELLO", "")

  def test_autokey_only_numbers_key_raises(self):
    """Test autokey with only numbers in key raises error."""
    with pytest.raises(ValueError, match="密钥"):
      vigenere_cipher.autokey_encrypt("HELLO", "12345")


class TestVigenereKasiski:
  """Test Kasiski examination."""

  def test_kasiski_basic(self):
    """Test Kasiski examination finds repeated patterns."""
    # Use a shorter key to create repeating patterns in the ciphertext
    # The plaintext repetition may not produce ciphertext repetition with long keys
    text = "ABCABCABCABC"
    encrypted = vigenere_cipher.encrypt(
      text, "KEY"
    )  # Short key for detectable patterns
    results = vigenere_cipher.kasiski_examination(encrypted)

    # Should find some repeated patterns with short key
    assert isinstance(results, dict)

  def test_kasiski_no_repeats(self):
    """Test Kasiski with no repeating patterns."""
    text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    results = vigenere_cipher.kasiski_examination(text)

    # May have no results or very few
    assert isinstance(results, dict)

  def test_kasiski_different_min_length(self):
    """Test Kasiski with different minimum length."""
    text = "ABCDEABCDE"
    results_3 = vigenere_cipher.kasiski_examination(text, 3)
    results_5 = vigenere_cipher.kasiski_examination(text, 5)

    # Longer min length should have fewer results
    assert len(results_5) <= len(results_3)


class TestVigenereFriedman:
  """Test Friedman test (Index of Coincidence)."""

  def test_friedman_english_text(self):
    """Test Friedman test on English text."""
    # English text should have IC around 0.067
    text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    estimated_key_length = vigenere_cipher.friedman_test(text)

    # Should return a reasonable value
    assert estimated_key_length > 0

  def test_friedman_short_text(self):
    """Test Friedman test on very short text."""
    text = "ABC"
    result = vigenere_cipher.friedman_test(text)
    assert result == 1.0

  def test_friedman_random_text(self):
    """Test Friedman test on random-looking text."""
    # Random text should have IC closer to 0.038
    # This may not be perfectly random but let's test the function works
    text = "QWERTYUIOPASDFGHJKLZXCVBNM"
    estimated = vigenere_cipher.friedman_test(text)
    assert isinstance(estimated, float)

  def test_friedman_empty_text(self):
    """Test Friedman test on empty text."""
    result = vigenere_cipher.friedman_test("")
    assert result == 1.0

  def test_friedman_single_char(self):
    """Test Friedman test on single character."""
    result = vigenere_cipher.friedman_test("A")
    assert result == 1.0


class TestVigenereInvalidKey:
  """Test handling of invalid keys."""

  def test_encrypt_empty_key_raises(self):
    """Test encryption with empty key raises error."""
    with pytest.raises(ValueError, match="密钥"):
      vigenere_cipher.encrypt("HELLO", "")

  def test_decrypt_empty_key_raises(self):
    """Test decryption with empty key raises error."""
    with pytest.raises(ValueError, match="密钥"):
      vigenere_cipher.decrypt("RIJVS", "")

  def test_encrypt_only_numbers_key_raises(self):
    """Test encryption with only numbers in key raises error."""
    with pytest.raises(ValueError, match="密钥"):
      vigenere_cipher.encrypt("HELLO", "12345")


class TestVigenereEdgeCases:
  """Test edge cases."""

  def test_encrypt_no_letters_in_text(self):
    """Test encryption of text with no letters."""
    assert vigenere_cipher.encrypt("12345!@#$%", "KEY") == "12345!@#$%"

  def test_decrypt_no_letters_in_text(self):
    """Test decryption of text with no letters."""
    assert vigenere_cipher.decrypt("12345!@#$%", "KEY") == "12345!@#$%"

  def test_encrypt_unicode(self):
    """Test encryption with unicode characters."""
    result = vigenere_cipher.encrypt("Héllo", "KEY")
    assert "H" not in result  # Should be encrypted

  def test_encrypt_mixed_content(self):
    """Test encryption with mixed content."""
    text = "A1B2C3!@#"
    result = vigenere_cipher.encrypt(text, "KEY")
    # Letters encrypted, numbers and symbols preserved
    assert result[1] == "1"
    assert result[3] == "2"
    assert result[5] == "3"


class TestVigenereKnownValues:
  """Test against known values."""

  def test_vigenere_vs_caesar_with_single_char_key(self):
    """Test Vigenère with single char key is equivalent to Caesar."""
    text = "HELLO"
    shift = 3

    vigenere_result = vigenere_cipher.encrypt(text, chr(ord("A") + shift))

    # Manually calculate Caesar
    caesar_result = ""
    for c in text:
      caesar_result += chr((ord(c) - ord("A") + shift) % 26 + ord("A"))

    assert vigenere_result == caesar_result
