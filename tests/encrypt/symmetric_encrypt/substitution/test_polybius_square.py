# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_polybius_square.py
# @time    : 2026/3/15
# @desc    : Tests for Polybius Square encryption/decryption

from crypt.encrypt.symmetric_encrypt.substitution import polybius_square

import pytest


class TestPolybiusEncrypt:
  """Test Polybius Square encryption."""

  def test_encrypt_basic(self):
    """Test basic Polybius encryption."""
    # H is at row 2, col 3 -> 23
    # E is at row 1, col 5 -> 15
    # L is at row 3, col 1 -> 31
    # L is at row 3, col 1 -> 31
    # O is at row 3, col 4 -> 34
    result = polybius_square.encrypt("HELLO")
    assert result == "23 15 31 31 34"

  def test_encrypt_lowercase(self):
    """Test Polybius encryption with lowercase."""
    result = polybius_square.encrypt("hello")
    assert result == "23 15 31 31 34"

  def test_encrypt_j_becomes_i(self):
    """Test that J becomes I in 5x5 square."""
    # J and I share the same position
    result_i = polybius_square.encrypt("I")
    result_j = polybius_square.encrypt("J")
    assert result_i == result_j

  def test_encrypt_empty_string(self):
    """Test Polybius encryption of empty string."""
    assert polybius_square.encrypt("") == ""

  def test_encrypt_with_key(self):
    """Test Polybius encryption with key."""
    result = polybius_square.encrypt("HELLO", key="KEYWORD")
    # Key changes the square layout
    # Should not be the same as without key
    result_no_key = polybius_square.encrypt("HELLO")
    assert result != result_no_key

  def test_encrypt_6x6(self):
    """Test Polybius encryption with 6x6 square."""
    result = polybius_square.encrypt("HELLO", size=6)
    # 6x6 includes digits, alphabet is A-Z then 0-9
    # H(7)->22, E(4)->15, L(11)->26, L->26, O(14)->33
    assert result == "22 15 26 26 33"

  def test_encrypt_with_custom_labels(self):
    """Test Polybius encryption with custom labels."""
    result = polybius_square.encrypt("HELLO", row_labels="ABCDE", col_labels="VWXYZ")
    # Using letters as coordinates: H->BX, E->AZ, L->CV, L->CV, O->CY
    assert result == "BX AZ CV CV CY"


class TestPolybiusDecrypt:
  """Test Polybius Square decryption."""

  def test_decrypt_basic(self):
    """Test basic Polybius decryption."""
    result = polybius_square.decrypt("23 15 31 31 34")
    assert result == "HELLO"

  def test_decrypt_no_spaces(self):
    """Test Polybius decryption without spaces."""
    result = polybius_square.decrypt("2315313134")
    assert result == "HELLO"

  def test_decrypt_with_key(self):
    """Test Polybius decryption with key."""
    encrypted = polybius_square.encrypt("HELLO", key="KEYWORD")
    result = polybius_square.decrypt(encrypted, key="KEYWORD")
    assert result == "HELLO"

  def test_decrypt_6x6(self):
    """Test Polybius decryption with 6x6 square."""
    encrypted = polybius_square.encrypt("HELLO", size=6)
    result = polybius_square.decrypt(encrypted, size=6)
    assert result == "HELLO"

  def test_decrypt_empty_string(self):
    """Test Polybius decryption of empty string."""
    assert polybius_square.decrypt("") == ""

  def test_decrypt_with_custom_labels(self):
    """Test Polybius decryption with custom labels."""
    encrypted = polybius_square.encrypt("HELLO", row_labels="ABCDE", col_labels="VWXYZ")
    result = polybius_square.decrypt(encrypted, row_labels="ABCDE", col_labels="VWXYZ")
    assert result == "HELLO"


class TestPolybiusRoundtrip:
  """Test Polybius Square encryption/decryption roundtrip."""

  @pytest.mark.parametrize(
    "text",
    [
      "HELLO",
      "WORLD",
      "TEST",
      "ABC",
      "",
    ],
  )
  def test_roundtrip_default(self, text):
    """Test roundtrip with default settings."""
    encrypted = polybius_square.encrypt(text)
    decrypted = polybius_square.decrypt(encrypted)
    assert decrypted == text

  @pytest.mark.parametrize(
    "text",
    [
      "HELLO",
      "WORLD",
      "TEST",
    ],
  )
  def test_roundtrip_with_key(self, text):
    """Test roundtrip with key."""
    encrypted = polybius_square.encrypt(text, key="KEYWORD")
    decrypted = polybius_square.decrypt(encrypted, key="KEYWORD")
    assert decrypted == text

  @pytest.mark.parametrize(
    "text",
    [
      "HELLO",
      "WORLD",
      "TEST",
    ],
  )
  def test_roundtrip_6x6(self, text):
    """Test roundtrip with 6x6 square."""
    encrypted = polybius_square.encrypt(text, size=6)
    decrypted = polybius_square.decrypt(encrypted, size=6)
    assert decrypted == text


class TestPolybiusPrintSquare:
  """Test Polybius Square printing."""

  def test_print_square_default(self):
    """Test printing default 5x5 square."""
    result = polybius_square.print_square()
    lines = result.split("\n")
    # Should have header + 5 rows
    assert len(lines) == 6

  def test_print_square_with_key(self):
    """Test printing square with key."""
    result = polybius_square.print_square(key="KEYWORD")
    # Should start with K, E, Y, W, O, R, D
    assert "K" in result
    assert "E" in result

  def test_print_square_6x6(self):
    """Test printing 6x6 square."""
    result = polybius_square.print_square(size=6)
    lines = result.split("\n")
    # Should have header + 6 rows
    assert len(lines) == 7

  def test_print_square_contains_numbers(self):
    """Test that square contains row/column numbers."""
    result = polybius_square.print_square()
    assert "1" in result
    assert "2" in result
    assert "3" in result
    assert "4" in result
    assert "5" in result


class TestPolybiusCustomOutput:
  """Test Polybius with custom output format."""

  def test_encrypt_with_custom_output(self):
    """Test encryption with letter coordinates."""
    result = polybius_square.encrypt_with_custom_output("HELLO")
    # Should use A-E for coordinates
    assert all(c in "ABCDE " for c in result)

  def test_decrypt_with_custom_input(self):
    """Test decryption with letter coordinates."""
    encrypted = polybius_square.encrypt_with_custom_output("HELLO")
    result = polybius_square.decrypt_with_custom_input(encrypted)
    assert result == "HELLO"

  def test_custom_roundtrip(self):
    """Test roundtrip with custom coordinates."""
    text = "HELLO"
    encrypted = polybius_square.encrypt_with_custom_output(text)
    decrypted = polybius_square.decrypt_with_custom_input(encrypted)
    assert decrypted == text


class TestPolybiusInvalidInput:
  """Test Polybius Square with invalid input."""

  def test_encrypt_invalid_size(self):
    """Test encryption with invalid size."""
    with pytest.raises(ValueError, match="方阵"):
      polybius_square.encrypt("HELLO", size=4)

  def test_decrypt_invalid_size(self):
    """Test decryption with invalid size."""
    with pytest.raises(ValueError, match="方阵"):
      polybius_square.decrypt("2315", size=4)


class TestPolybiusEdgeCases:
  """Test edge cases."""

  def test_encrypt_non_alpha_only(self):
    """Test encryption of string with no letters."""
    assert polybius_square.encrypt("12345!@#$%") == ""

  def test_encrypt_unicode(self):
    """Test encryption with unicode characters."""
    result = polybius_square.encrypt("Héllo")
    # é should be ignored (not in alphabet)
    assert "é" not in result

  def test_decrypt_incomplete_pair(self):
    """Test decryption with incomplete pair at end."""
    # "231" has incomplete pair "1"
    result = polybius_square.decrypt("231")
    # Should just decode "23" -> H
    assert result == "H"

  def test_decrypt_invalid_coordinates(self):
    """Test decryption with invalid coordinates."""
    # "99" is out of range for 5x5
    result = polybius_square.decrypt("99")
    assert result == ""


class TestPolybiusKnownValues:
  """Test against known Polybius values."""

  def test_known_encryption(self):
    """Test known encryption values."""
    # In standard Polybius square:
    # A=11, B=12, C=13, D=14, E=15
    # F=21, G=22, H=23, I/J=24, K=25
    # etc.
    result = polybius_square.encrypt("AB")
    assert result == "11 12"

  def test_known_decryption(self):
    """Test known decryption values."""
    result = polybius_square.decrypt("11 12 13")
    assert result == "ABC"


class TestPolybiusProperties:
  """Test properties of Polybius Square."""

  def test_i_j_equivalence(self):
    """Test that I and J are equivalent in 5x5."""
    result_i = polybius_square.encrypt("I")
    result_j = polybius_square.encrypt("J")
    assert result_i == result_j

  def test_deterministic(self):
    """Test that encryption is deterministic."""
    text = "HELLO"
    result1 = polybius_square.encrypt(text)
    result2 = polybius_square.encrypt(text)
    assert result1 == result2

  def test_output_format(self):
    """Test that output format is correct."""
    result = polybius_square.encrypt("HELLO")
    # Should be pairs of digits separated by spaces
    parts = result.split()
    for part in parts:
      assert len(part) == 2
      assert part.isdigit()
