"""Tests for Playfair cipher implementation."""

from crypt.encrypt.symmetric_encrypt.block_cipher.playfair_cipher import (
  _create_matrix,
  _find_position,
  _prepare_text,
  decrypt,
  encrypt,
  print_matrix,
)

import pytest


class TestCreateMatrix:
  """Test matrix creation."""

  def test_create_matrix_basic(self):
    """Test basic matrix creation."""
    matrix = _create_matrix("KEYWORD")
    assert len(matrix) == 5
    assert all(len(row) == 5 for row in matrix)

  def test_matrix_contains_all_letters(self):
    """Test matrix contains all 25 letters (I/J shared)."""
    matrix = _create_matrix("KEYWORD")
    all_chars = set()
    for row in matrix:
      all_chars.update(row)
    assert all_chars == set("ABCDEFGHIKLMNOPQRSTUVWXYZ")
    assert "J" not in all_chars

  def test_matrix_key_first(self):
    """Test that key letters appear first in matrix."""
    matrix = _create_matrix("KEYWORD")
    # K, E, Y, W, O, R, D should be in first positions
    flat = [c for row in matrix for c in row]
    assert flat[:7] == ["K", "E", "Y", "W", "O", "R", "D"]

  def test_matrix_ignores_duplicates(self):
    """Test that duplicate key letters are ignored."""
    matrix = _create_matrix("HELLO")
    flat = [c for row in matrix for c in row]
    # H, E, L should appear, but second L should be skipped
    assert flat[:4] == ["H", "E", "L", "O"]

  def test_matrix_j_becomes_i(self):
    """Test that J in key becomes I."""
    matrix = _create_matrix("JAZZ")
    flat = [c for row in matrix for c in row]
    assert flat[0] == "I"  # J becomes I
    assert flat[1] == "A"
    assert flat[2] == "Z"


class TestFindPosition:
  """Test position finding in matrix."""

  def test_find_position_basic(self):
    """Test finding position of a character."""
    matrix = _create_matrix("KEYWORD")
    # K should be at (0, 0)
    assert _find_position(matrix, "K") == (0, 0)
    # A should be in position
    pos = _find_position(matrix, "A")
    assert isinstance(pos, tuple)
    assert len(pos) == 2

  def test_find_position_j_becomes_i(self):
    """Test that finding J returns position of I."""
    matrix = _create_matrix("KEYWORD")
    pos_j = _find_position(matrix, "J")
    pos_i = _find_position(matrix, "I")
    assert pos_j == pos_i

  def test_find_position_invalid_char(self):
    """Test that invalid character raises ValueError."""
    matrix = _create_matrix("KEYWORD")
    with pytest.raises(ValueError, match="字符"):
      _find_position(matrix, "1")


class TestPrepareText:
  """Test text preparation."""

  def test_prepare_text_basic(self):
    """Test basic text preparation."""
    result = _prepare_text("HELLO")
    assert result == ["HE", "LX", "LO"]

  def test_prepare_text_odd_length(self):
    """Test text with odd length gets X padding."""
    result = _prepare_text("ABC")
    assert result == ["AB", "CX"]

  def test_prepare_text_double_letters(self):
    """Test double letters get X inserted."""
    result = _prepare_text("BALLOON")
    # BA, LX, LO, ON (double L gets X inserted)
    assert result == ["BA", "LX", "LO", "ON"]

  def test_prepare_text_j_becomes_i(self):
    """Test J becomes I in preparation."""
    result = _prepare_text("JAIL")
    # IA, IL (J becomes I, but II would have X inserted)
    assert "J" not in "".join(result)

  def test_prepare_text_removes_non_alpha(self):
    """Test non-alphabetic characters are removed."""
    result = _prepare_text("HELLO, WORLD!")
    assert len(result) == 6  # HE LL OW OR LD with padding

  def test_prepare_text_empty(self):
    """Test empty text returns empty list."""
    result = _prepare_text("")
    assert result == []


class TestPlayfairEncrypt:
  """Test Playfair encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption."""
    result = encrypt("HELLO", "KEYWORD")
    assert isinstance(result, str)
    assert len(result) == 6  # Padded to even length

  def test_encrypt_with_spaces(self):
    """Test encryption handles spaces."""
    result = encrypt("HELLO WORLD", "KEYWORD")
    assert isinstance(result, str)
    assert " " not in result

  def test_encrypt_known_value(self):
    """Test encryption with known expected value."""
    # With KEYWORD key, HELLO should encrypt to specific value
    result = encrypt("HELLO", "KEYWORD")
    # Based on the docstring example: HELLO with KEYWORD should give GYIZSC
    assert result == "GYIZSC"

  def test_encrypt_double_letters(self):
    """Test encryption with double letters."""
    result = encrypt("BALLOON", "PLAYFAIR")
    assert isinstance(result, str)
    assert len(result) == 8


class TestPlayfairDecrypt:
  """Test Playfair decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    encrypted = encrypt("HELLO", "KEYWORD")
    decrypted = decrypt(encrypted, "KEYWORD")
    assert isinstance(decrypted, str)

  def test_decrypt_roundtrip(self):
    """Test encrypt/decrypt roundtrip."""
    original = "MEETMEATTHEPARK"
    key = "MONARCHY"
    encrypted = encrypt(original, key)
    decrypted = decrypt(encrypted, key)
    # Note: X padding may be added, so check prefix
    assert decrypted.startswith(original) or original.startswith(decrypted)

  def test_decrypt_known_value(self):
    """Test decryption of known ciphertext."""
    result = decrypt("GYIZSC", "KEYWORD")
    # Should decrypt back to HELXLO (X was inserted during encryption due to double L)
    assert result == "HELXLO"


class TestPrintMatrix:
  """Test matrix printing."""

  def test_print_matrix(self):
    """Test matrix printing returns string."""
    result = print_matrix("KEYWORD")
    assert isinstance(result, str)
    assert "\n" in result
    lines = result.split("\n")
    assert len(lines) == 5


class TestPlayfairEdgeCases:
  """Test edge cases."""

  def test_encrypt_empty_string(self):
    """Test encryption of empty string."""
    result = encrypt("", "KEYWORD")
    assert result == ""

  def test_encrypt_single_letter(self):
    """Test encryption of single letter."""
    result = encrypt("A", "KEYWORD")
    assert len(result) == 2  # Padded with X

  def test_encrypt_same_row(self):
    """Test encryption of letters in same row."""
    result = encrypt("AB", "KEYWORD")
    assert isinstance(result, str)

  def test_encrypt_same_column(self):
    """Test encryption of letters in same column."""
    result = encrypt("AF", "KEYWORD")
    assert isinstance(result, str)

  def test_encrypt_rectangle(self):
    """Test encryption of letters forming rectangle."""
    result = encrypt("AC", "KEYWORD")
    assert isinstance(result, str)

  def test_key_with_numbers(self):
    """Test key containing numbers."""
    result = encrypt("HELLO", "KEY123")
    assert isinstance(result, str)

  def test_lowercase_input(self):
    """Test lowercase input works."""
    result_lower = encrypt("hello", "keyword")
    result_upper = encrypt("HELLO", "KEYWORD")
    assert result_lower == result_upper
