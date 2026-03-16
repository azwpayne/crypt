# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_rot13.py
# @time    : 2026/3/15
# @desc    : Tests for ROT13 encryption/decryption

from crypt.encrypt.symmetric_encrypt.substitution import rot13

import pytest


class TestRot13Encrypt:
  """Test ROT13 encryption."""

  def test_encrypt_basic(self):
    """Test basic ROT13 encryption."""
    assert rot13.encrypt("HELLO") == "URYYB"

  def test_encrypt_lowercase(self):
    """Test ROT13 with lowercase."""
    assert rot13.encrypt("hello") == "uryyb"

  def test_encrypt_mixed_case(self):
    """Test ROT13 with mixed case."""
    assert rot13.encrypt("Hello") == "Uryyb"
    assert rot13.encrypt("HeLLo") == "UrYYb"

  def test_encrypt_preserves_non_alpha(self):
    """Test ROT13 preserves non-alphabetic characters."""
    assert rot13.encrypt("HELLO, WORLD!") == "URYYB, JBEYQ!"
    assert rot13.encrypt("12345") == "12345"

  def test_encrypt_empty_string(self):
    """Test ROT13 of empty string."""
    assert rot13.encrypt("") == ""

  def test_encrypt_all_letters(self):
    """Test ROT13 of all letters."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = rot13.encrypt(alphabet)
    expected = "NOPQRSTUVWXYZABCDEFGHIJKLM"
    assert result == expected

  def test_encrypt_self_inverse(self):
    """Test that ROT13 is self-inverse (encrypt twice = original)."""
    text = "HELLO WORLD"
    once = rot13.encrypt(text)
    twice = rot13.encrypt(once)
    assert twice == text


class TestRot13Decrypt:
  """Test ROT13 decryption."""

  def test_decrypt_basic(self):
    """Test basic ROT13 decryption."""
    assert rot13.decrypt("URYYB") == "HELLO"

  def test_decrypt_lowercase(self):
    """Test ROT13 decryption with lowercase."""
    assert rot13.decrypt("uryyb") == "hello"

  def test_decrypt_preserves_non_alpha(self):
    """Test ROT13 decryption preserves non-alphabetic characters."""
    assert rot13.decrypt("URYYB, JBEYQ!") == "HELLO, WORLD!"

  def test_decrypt_empty_string(self):
    """Test ROT13 decryption of empty string."""
    assert rot13.decrypt("") == ""

  def test_decrypt_is_encrypt(self):
    """Test that decrypt is the same as encrypt for ROT13."""
    text = "TEST MESSAGE"
    encrypted = rot13.encrypt(text)
    decrypted = rot13.decrypt(text)
    assert encrypted == decrypted


class TestRot13Roundtrip:
  """Test ROT13 roundtrip."""

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
    """Test that ROT13(RROT13(text)) == text."""
    encrypted = rot13.encrypt(text)
    decrypted = rot13.decrypt(encrypted)
    assert decrypted == text


class TestRot13KnownValues:
  """Test against known ROT13 values."""

  @pytest.mark.parametrize(
    ("plaintext", "expected"),
    [
      ("A", "N"),
      ("B", "O"),
      ("N", "A"),
      ("M", "Z"),
      ("Z", "M"),
      ("NO", "AB"),
      ("AB", "NO"),
      ("Why", "Jul"),
      ("Jul", "Why"),
    ],
  )
  def test_known_values(self, plaintext, expected):
    """Test against known ROT13 transformations."""
    assert rot13.encrypt(plaintext) == expected

  def test_rot13_pangram(self):
    """Test ROT13 on a pangram."""
    # "The quick brown fox jumps over the lazy dog"
    text = "The quick brown fox jumps over the lazy dog"
    expected = "Gur dhvpx oebja sbk whzcf bire gur ynml qbt"
    assert rot13.encrypt(text) == expected


class TestRot13EdgeCases:
  """Test edge cases."""

  def test_encrypt_non_alpha_only(self):
    """Test ROT13 of string with no letters."""
    assert rot13.encrypt("12345!@#$%") == "12345!@#$%"

  def test_encrypt_unicode(self):
    """Test ROT13 with unicode characters."""
    result = rot13.encrypt("Héllo")
    # é should be preserved
    assert "é" in result

  def test_single_char_each(self):
    """Test ROT13 on individual characters."""
    for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
      result = rot13.encrypt(char)
      # A-M should become N-Z, N-Z should become A-M
      if ord(char) <= ord("M"):
        assert result == chr(ord(char) + 13)
      else:
        assert result == chr(ord(char) - 13)


class TestRot13Properties:
  """Test mathematical properties of ROT13."""

  def test_involution(self):
    """Test that ROT13 is an involution (self-inverse)."""
    # For any text, ROT13(ROT13(text)) == text
    texts = ["HELLO", "abc", "123", "Mix3d!"]
    for text in texts:
      assert rot13.encrypt(rot13.encrypt(text)) == text

  def test_commutative(self):
    """Test that ROT13 is commutative with itself."""
    text = "HELLO"
    # Applying ROT13 multiple times
    result1 = rot13.encrypt(rot13.encrypt(text))
    result2 = rot13.encrypt(rot13.encrypt(text))
    assert result1 == result2

  def test_deterministic(self):
    """Test that ROT13 is deterministic."""
    text = "HELLO"
    result1 = rot13.encrypt(text)
    result2 = rot13.encrypt(text)
    assert result1 == result2

  def test_length_preservation(self):
    """Test that ROT13 preserves string length."""
    text = "HELLO WORLD 123!"
    result = rot13.encrypt(text)
    assert len(result) == len(text)

  def test_case_preservation(self):
    """Test that ROT13 preserves case of letters."""
    result = rot13.encrypt("Hello")
    assert result[0].isupper()
    assert result[1].islower()


class TestRot13VsCaesar:
  """Test ROT13 relationship to Caesar cipher."""

  def test_rot13_is_caesar_13(self):
    """Test that ROT13 is equivalent to Caesar cipher with shift 13."""
    # Import Caesar for comparison
    from crypt.encrypt.symmetric_encrypt.substitution import caesar_cipher

    text = "HELLO WORLD"
    rot13_result = rot13.encrypt(text)
    caesar_result = caesar_cipher.encrypt(text, 13)

    assert rot13_result == caesar_result
