"""Tests for Polybius Square cipher."""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.stream_cipher.polybius_square import (
  decrypt,
  decrypt_with_custom_input,
  encrypt,
  encrypt_with_custom_output,
  print_square,
)

import pytest


class TestPolybiusSquareEncrypt:
  """Test Polybius Square encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption."""
    result = encrypt("HELLO", size=5)
    assert result == "23 15 31 31 34"

  def test_encrypt_with_key(self):
    """Test encryption with key."""
    result = encrypt("HELLO", key="KEYWORD", size=5)
    assert isinstance(result, str)
    assert len(result.split()) == 5

  def test_encrypt_lowercase(self):
    """Test encryption with lowercase input."""
    result_lower = encrypt("hello", size=5)
    result_upper = encrypt("HELLO", size=5)
    assert result_lower == result_upper

  def test_encrypt_j_becomes_i(self):
    """Test that J becomes I in 5x5 mode."""
    result = encrypt("JAIL", size=5)
    assert isinstance(result, str)
    assert len(result.split()) == 4

  def test_encrypt_with_numbers_6x6(self):
    """Test encryption with numbers in 6x6 mode."""
    result = encrypt("HELLO1", size=6)
    assert isinstance(result, str)
    assert len(result.split()) == 6

  def test_encrypt_empty_string(self):
    """Test encryption of empty string."""
    result = encrypt("", size=5)
    assert result == ""

  def test_encrypt_skips_spaces_by_default(self):
    """Test that spaces are skipped in default (non-strict) mode."""
    result = encrypt("HELLO WORLD", size=5)
    assert result == "23 15 31 31 34 52 34 42 31 14"

  def test_encrypt_skips_non_alpha_by_default(self):
    """Test that non-alphabetic chars are skipped in default mode."""
    result = encrypt("HELLO123!@#", size=5)
    assert result == "23 15 31 31 34"

  def test_encrypt_strict_rejects_spaces(self):
    """Test strict mode rejects spaces."""
    with pytest.raises(ValueError, match="cannot be encoded"):
      encrypt("HELLO WORLD", size=5, strict=True)

  def test_encrypt_strict_rejects_non_alpha(self):
    """Test strict mode rejects non-alphabetic characters."""
    with pytest.raises(ValueError, match="cannot be encoded"):
      encrypt("HELLO123", size=5, strict=True)


class TestPolybiusSquareDecrypt:
  """Test Polybius Square decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    encrypted = encrypt("HELLO", size=5)
    decrypted = decrypt(encrypted, size=5)
    assert decrypted == "HELLO"

  def test_decrypt_with_key(self):
    """Test decryption with key."""
    original = "HELLO"
    key = "KEYWORD"
    encrypted = encrypt(original, key=key, size=5)
    decrypted = decrypt(encrypted, key=key, size=5)
    assert decrypted == original

  def test_decrypt_roundtrip(self):
    """Test roundtrip encryption/decryption."""
    original = "ATTACK"
    encrypted = encrypt(original, size=5)
    decrypted = decrypt(encrypted, size=5)
    assert decrypted == original

  def test_decrypt_6x6(self):
    """Test decryption with 6x6 square."""
    original = "TEST123"
    encrypted = encrypt(original, size=6)
    decrypted = decrypt(encrypted, size=6)
    assert decrypted == original

  def test_decrypt_empty_string(self):
    """Test decryption of empty string."""
    result = decrypt("", size=5)
    assert result == ""

  def test_decrypt_strict_rejects_odd_length(self):
    """Test strict mode rejects odd-length input."""
    with pytest.raises(ValueError, match="must be even"):
      decrypt("123", size=5, strict=True)

  def test_decrypt_strict_rejects_invalid_coordinates(self):
    """Test strict mode rejects invalid coordinate characters."""
    with pytest.raises(ValueError, match="Invalid coordinate pair"):
      decrypt("99 99", size=5, strict=True)


class TestPolybiusSquareModes:
  """Test different Polybius Square modes."""

  def test_5x5_mode(self):
    """Test 5x5 mode (25 chars, I/J shared)."""
    result = encrypt("ABCDEFGHIKLMNOPQRSTUVWXYZ", size=5)
    coords = result.split()
    assert len(coords) == 25

  def test_6x6_mode(self):
    """Test 6x6 mode (36 chars, includes digits)."""
    result = encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", size=6)
    coords = result.split()
    assert len(coords) == 36

  def test_invalid_size(self):
    """Test invalid square size."""
    with pytest.raises(ValueError, match="方阵大小必须是5或6"):
      encrypt("TEST", size=4)


class TestPolybiusSquareEdgeCases:
  """Test edge cases."""

  def test_single_character(self):
    """Test single character."""
    result = encrypt("A", size=5)
    assert result == "11"

  def test_long_message(self):
    """Test long message."""
    message = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    encrypted = encrypt(message, size=5)
    decrypted = decrypt(encrypted, size=5)
    expected = message.replace("J", "I")
    assert decrypted == expected

  def test_with_special_characters_filtered(self):
    """Test that special characters are filtered in non-strict mode."""
    message = "HELLO, WORLD!"
    encrypted = encrypt(message, size=5)
    assert encrypted == "23 15 31 31 34 52 34 42 31 14"


class TestPolybiusSquareCustomLabels:
  """Test custom label functions."""

  def test_encrypt_with_custom_output(self):
    result = encrypt_with_custom_output("HELLO")
    assert result == "BC AE CA CA CD"

  def test_decrypt_with_custom_input(self):
    encrypted = encrypt_with_custom_output("HELLO")
    decrypted = decrypt_with_custom_input(encrypted)
    assert decrypted == "HELLO"

  def test_print_square_default(self):
    result = print_square()
    assert "1 2 3 4 5" in result
    assert "A" in result

  def test_print_square_with_key(self):
    result = print_square("KEYWORD")
    assert "K" in result

  def test_print_square_6x6(self):
    result = print_square(size=6)
    assert "1 2 3 4 5 6" in result


class TestPolybiusSquareDecryptEdgeCases:
  """Test decryption edge cases."""

  def test_decrypt_skips_invalid_coordinates_by_default(self):
    result = decrypt("99 99", size=5)
    assert result == ""

  def test_decrypt_empty_input(self):
    result = decrypt("", size=5)
    assert result == ""

  def test_decrypt_with_custom_labels(self):
    encrypted = "BC AE CA CA CD"
    result = decrypt(encrypted, row_labels="ABCDE", col_labels="ABCDE")
    assert result == "HELLO"

  def test_decrypt_invalid_custom_labels_skipped(self):
    result = decrypt("ZZ", size=5, row_labels="ABCDE", col_labels="ABCDE")
    assert result == ""

  def test_decrypt_odd_length_not_strict(self):
    result = decrypt("123", size=5)
    assert result == "B"
