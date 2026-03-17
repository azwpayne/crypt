"""Tests for Simple Substitution cipher implementation."""

from crypt.encrypt.symmetric_encrypt.stream_cipher.simple_substitution import (
  _validate_key,
  decrypt,
  encrypt,
  frequency_analysis,
  generate_key_from_keyword,
  generate_random_key,
)

import pytest


class TestValidateKey:
  """Test key validation."""

  def test_validate_valid_key(self):
    """Test validation of valid key."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    _validate_key(key)  # Should not raise

  def test_validate_key_too_short(self):
    """Test validation of key that is too short."""
    with pytest.raises(ValueError, match="26"):
      _validate_key("SHORT")

  def test_validate_key_too_long(self):
    """Test validation of key that is too long."""
    with pytest.raises(ValueError, match="26"):
      _validate_key("QWERTYUIOPASDFGHJKLZXCVBNMEXTRA")

  def test_validate_key_missing_letters(self):
    """Test validation of key missing letters."""
    with pytest.raises(ValueError, match="A-Z"):
      # Missing M, has Q twice
      _validate_key("QWERTYUIOPASDFGHJKLZXCVBNQ")


class TestEncrypt:
  """Test encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    result = encrypt("HELLO", key)
    # H->I, E->T, L->S, L->S, O->G
    assert result == "ITSSG"

  def test_encrypt_with_spaces(self):
    """Test encryption preserves spaces."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    result = encrypt("HELLO WORLD", key)
    assert " " in result

  def test_encrypt_preserves_punctuation(self):
    """Test encryption preserves punctuation."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    result = encrypt("HELLO, WORLD!", key)
    assert "," in result
    assert "!" in result

  def test_encrypt_lowercase(self):
    """Test encryption handles lowercase."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    result = encrypt("hello", key)
    assert result == "itssg"

  def test_encrypt_empty(self):
    """Test encryption of empty string."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    result = encrypt("", key)
    assert result == ""

  def test_encrypt_no_letters(self):
    """Test encryption of string with no letters."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    result = encrypt("123!@#", key)
    assert result == "123!@#"


class TestDecrypt:
  """Test decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    encrypted = encrypt("HELLO", key)
    decrypted = decrypt(encrypted, key)
    assert decrypted == "HELLO"

  def test_decrypt_roundtrip(self):
    """Test encrypt/decrypt roundtrip."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    original = "ATTACKATDAWN"
    encrypted = encrypt(original, key)
    decrypted = decrypt(encrypted, key)
    assert decrypted == original

  def test_decrypt_lowercase(self):
    """Test decryption handles lowercase."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    original = "hello"
    encrypted = encrypt(original, key)
    decrypted = decrypt(encrypted, key)
    assert decrypted == original


class TestGenerateRandomKey:
  """Test random key generation."""

  def test_generate_random_key_length(self):
    """Test random key has correct length."""
    key = generate_random_key()
    assert len(key) == 26

  def test_generate_random_key_valid(self):
    """Test generated key is valid."""
    key = generate_random_key()
    _validate_key(key)  # Should not raise

  def test_generate_random_key_unique(self):
    """Test that multiple keys are different."""
    key1 = generate_random_key()
    key2 = generate_random_key()
    assert key1 != key2


class TestGenerateKeyFromKeyword:
  """Test keyword-based key generation."""

  def test_generate_from_keyword_basic(self):
    """Test key generation from keyword."""
    key = generate_key_from_keyword("KEYWORD")
    assert key.startswith("KEYWORD")
    assert len(key) == 26

  def test_generate_from_keyword_removes_duplicates(self):
    """Test duplicate letters in keyword are removed."""
    key = generate_key_from_keyword("BALLOON")
    # Should be "BALON" followed by remaining letters
    assert key.startswith("BALON")

  def test_generate_from_keyword_ignores_non_alpha(self):
    """Test non-alphabetic characters are ignored."""
    key = generate_key_from_keyword("KEY123!")
    assert key.startswith("KEY")

  def test_generate_from_keyword_completes_alphabet(self):
    """Test generated key contains all letters."""
    key = generate_key_from_keyword("KEYWORD")
    _validate_key(key)  # Should not raise


class TestFrequencyAnalysis:
  """Test frequency analysis."""

  def test_frequency_analysis_basic(self):
    """Test basic frequency analysis."""
    text = "HELLO"
    freq = frequency_analysis(text)
    assert len(freq) == 4  # H, E, L, O
    assert freq["L"] == 40.0  # L appears twice out of 5 letters = 40%

  def test_frequency_analysis_empty(self):
    """Test frequency analysis of empty string."""
    freq = frequency_analysis("")
    assert freq == {}

  def test_frequency_analysis_no_letters(self):
    """Test frequency analysis of string with no letters."""
    freq = frequency_analysis("123!@#")
    assert freq == {}

  def test_frequency_analysis_ignores_case(self):
    """Test frequency analysis is case insensitive."""
    freq_lower = frequency_analysis("hello")
    freq_upper = frequency_analysis("HELLO")
    assert freq_lower == freq_upper


class TestSimpleSubstitutionEdgeCases:
  """Test edge cases."""

  def test_single_letter(self):
    """Test single letter encryption."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    result = encrypt("A", key)
    assert result == "Q"

  def test_full_alphabet(self):
    """Test encryption of full alphabet."""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    original = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encrypted = encrypt(original, key)
    assert encrypted == key
