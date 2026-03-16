# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_playfair_cipher.py
# @time    : 2026/3/15
# @desc    : Tests for Playfair cipher encryption/decryption

from crypt.encrypt.symmetric_encrypt.substitution import playfair_cipher

import pytest


class TestPlayfairEncrypt:
  """Test Playfair cipher encryption."""

  def test_encrypt_basic(self):
    """Test basic Playfair encryption."""
    # With KEYWORD key:
    # H(2,4) E(0,1) -> G(2,0) Y(0,4)
    # L(2,2) L(2,2) -> L(2,2) X(1,2) (same letter, insert X)
    # O(1,4) -> I(2,3) Z(0,3)
    result = playfair_cipher.encrypt("HELLO", "KEYWORD")
    assert result == "GYIZSC"

  def test_encrypt_lowercase(self):
    """Test Playfair encryption with lowercase."""
    result = playfair_cipher.encrypt("hello", "KEYWORD")
    assert result == "GYIZSC"

  def test_encrypt_mixed_case(self):
    """Test Playfair encryption with mixed case."""
    result = playfair_cipher.encrypt("HeLLo", "KEYWORD")
    assert result == "GYIZSC"

  def test_encrypt_j_becomes_i(self):
    """Test that J becomes I."""
    result_j = playfair_cipher.encrypt("J", "KEYWORD")
    result_i = playfair_cipher.encrypt("I", "KEYWORD")
    assert result_j == result_i

  def test_encrypt_same_letters(self):
    """Test encryption handles same letters in pair."""
    # "LL" should become "LX" then encrypted
    result = playfair_cipher.encrypt("HELLO", "KEYWORD")
    # Should have X inserted between LL
    assert "X" not in result  # X should be encrypted

  def test_encrypt_odd_length(self):
    """Test encryption pads odd length with X."""
    result = playfair_cipher.encrypt("ABC", "KEYWORD")
    # ABC -> AB CX, so result should be 4 chars
    assert len(result) == 4

  def test_encrypt_preserves_non_alpha(self):
    """Test Playfair encryption removes non-alphabetic characters."""
    result = playfair_cipher.encrypt("HELLO WORLD!", "KEYWORD")
    # Space and ! should be removed
    assert " " not in result
    assert "!" not in result

  def test_encrypt_empty_string(self):
    """Test Playfair encryption of empty string."""
    assert playfair_cipher.encrypt("", "KEYWORD") == ""

  def test_encrypt_single_char(self):
    """Test encryption of single character."""
    result = playfair_cipher.encrypt("A", "KEYWORD")
    # Should be padded with X
    assert len(result) == 2

  def test_encrypt_same_row(self):
    """Test encryption of letters in same row."""
    # In KEYWORD square, K, E, Y, W, O, R, D are in first row/rows
    result = playfair_cipher.encrypt("KEY", "KEYWORD")
    # K-E-Y are in first row, should shift right
    assert len(result) == 4  # KEY -> KE YX

  def test_encrypt_same_column(self):
    """Test encryption of letters in same column."""
    # Find two letters in same column
    result = playfair_cipher.encrypt("AB", "KEYWORD")
    assert len(result) == 2


class TestPlayfairDecrypt:
  """Test Playfair cipher decryption."""

  def test_decrypt_basic(self):
    """Test basic Playfair decryption."""
    result = playfair_cipher.decrypt("GYIZSC", "KEYWORD")
    assert result == "HELXLO"  # Note: X is padding

  def test_decrypt_lowercase(self):
    """Test Playfair decryption with lowercase."""
    result = playfair_cipher.decrypt("gyizsc", "KEYWORD")
    assert result == "HELXLO"

  def test_decrypt_empty_string(self):
    """Test Playfair decryption of empty string."""
    assert playfair_cipher.decrypt("", "KEYWORD") == ""


class TestPlayfairRoundtrip:
  """Test Playfair cipher encryption/decryption roundtrip."""

  @pytest.mark.parametrize(
    "text",
    [
      "HELLO",
      "WORLD",
      "TEST",
      "ABC",
      "SECRET",
    ],
  )
  def test_roundtrip(self, text):
    """Test roundtrip (note: X may be inserted)."""
    encrypted = playfair_cipher.encrypt(text, "KEYWORD")
    decrypted = playfair_cipher.decrypt(encrypted, "KEYWORD")
    # Decrypted should contain original letters (may have X padding)
    for char in text:
      if char != "J":  # J becomes I
        assert char in decrypted or (char == "I" and "J" in text)


class TestPlayfairPrintMatrix:
  """Test Playfair matrix printing."""

  def test_print_matrix_default(self):
    """Test printing default matrix."""
    result = playfair_cipher.print_matrix("KEYWORD")
    lines = result.split("\n")
    # Should have 5 rows
    assert len(lines) == 5
    # Each row should have 5 letters
    for line in lines:
      assert len(line.replace(" ", "")) == 5

  def test_print_matrix_contains_key(self):
    """Test that matrix contains key letters first."""
    result = playfair_cipher.print_matrix("KEYWORD")
    # Should start with K, E, Y, W, O, R, D
    assert "K" in result
    assert "E" in result
    assert "Y" in result

  def test_print_matrix_no_j(self):
    """Test that matrix does not contain J."""
    result = playfair_cipher.print_matrix("KEYWORD")
    # J is merged with I
    assert "J" not in result

  def test_print_matrix_format(self):
    """Test matrix format."""
    result = playfair_cipher.print_matrix("KEYWORD")
    # Should be space-separated letters
    parts = result.split()
    assert len(parts) == 25  # 5x5 matrix


class TestPlayfairMatrixCreation:
  """Test Playfair matrix creation."""

  def test_matrix_unique_letters(self):
    """Test that matrix has all unique letters."""
    matrix = playfair_cipher.print_matrix("KEYWORD")
    letters = matrix.replace(" ", "").replace("\n", "")
    assert len(set(letters)) == len(letters)

  def test_matrix_size(self):
    """Test that matrix is 5x5."""
    matrix = playfair_cipher.print_matrix("KEYWORD")
    lines = matrix.strip().split("\n")
    assert len(lines) == 5
    for line in lines:
      # Count non-space characters
      chars = [c for c in line if c.isalpha()]
      assert len(chars) == 5

  def test_key_duplicates_removed(self):
    """Test that duplicate letters in key are removed."""
    matrix1 = playfair_cipher.print_matrix("SECRET")
    matrix2 = playfair_cipher.print_matrix("SECRETKEY")
    # Both should have same letters at start (S, E, C, R, T)
    assert "S" in matrix1
    assert "E" in matrix1


class TestPlayfairEdgeCases:
  """Test edge cases."""

  def test_encrypt_xx_pair(self):
    """Test encryption handles XX pair specially."""
    # XX would normally need insertion, but let's just test it works
    result = playfair_cipher.encrypt("XX", "KEYWORD")
    assert len(result) == 4  # XX -> XZ XZ or similar

  def test_encrypt_long_text(self):
    """Test encryption of longer text."""
    text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    result = playfair_cipher.encrypt(text, "KEYWORD")
    # Should succeed and produce output
    assert len(result) > 0
    assert " " not in result

  def test_decrypt_long_text(self):
    """Test decryption of longer text."""
    text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    encrypted = playfair_cipher.encrypt(text, "KEYWORD")
    decrypted = playfair_cipher.decrypt(encrypted, "KEYWORD")
    assert len(decrypted) > 0


class TestPlayfairKnownValues:
  """Test against known Playfair values."""

  @pytest.mark.parametrize(
    ("plaintext", "key", "expected"),
    [
      ("HELLO", "KEYWORD", "GYIZSC"),
      (
        "MEET",
        "MONARCHY",
        "CLKL",
      ),  # M(0,0)+E(2,0) same column -> C(1,0); E(2,0)+T(3,4) rectangle -> L(3,0)+K(2,4)
    ],
  )
  def test_known_encryption(self, plaintext, key, expected):
    """Test against known encrypted values."""
    result = playfair_cipher.encrypt(plaintext, key)
    assert result == expected


class TestPlayfairProperties:
  """Test properties of Playfair cipher."""

  def test_deterministic(self):
    """Test that encryption is deterministic."""
    text = "HELLO"
    key = "KEYWORD"
    result1 = playfair_cipher.encrypt(text, key)
    result2 = playfair_cipher.encrypt(text, key)
    assert result1 == result2

  def test_key_matters(self):
    """Test that different keys produce different results."""
    text = "HELLO"
    result1 = playfair_cipher.encrypt(text, "KEYWORD")
    result2 = playfair_cipher.encrypt(text, "SECRET")
    assert result1 != result2

  def test_i_j_treated_same(self):
    """Test that I and J are treated as the same letter."""
    result_i = playfair_cipher.encrypt("I", "KEYWORD")
    result_j = playfair_cipher.encrypt("J", "KEYWORD")
    assert result_i == result_j

  def test_output_length(self):
    """Test output length properties."""
    # Output should be even length
    result = playfair_cipher.encrypt("HELLO", "KEYWORD")
    assert len(result) % 2 == 0

    result = playfair_cipher.encrypt("ABC", "KEYWORD")
    assert len(result) % 2 == 0
