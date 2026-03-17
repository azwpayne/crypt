"""Tests for Atbash cipher implementation."""

from crypt.encrypt.symmetric_encrypt.stream_cipher.atbash_cipher import (
  _create_atbash_table,
  decrypt,
  encrypt,
  encrypt_hebrew,
)


class TestCreateAtbashTable:
  """Test atbash table creation."""

  def test_create_table(self):
    """Test that translation table is created."""
    table = _create_atbash_table()
    assert isinstance(table, dict)


class TestAtbashEncrypt:
  """Test Atbash encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption."""
    result = encrypt("HELLO")
    assert result == "SVOOL"  # H->S, E->V, L->O, L->O, O->L

  def test_encrypt_lowercase(self):
    """Test encryption of lowercase."""
    result = encrypt("hello")
    assert result == "svool"

  def test_encrypt_mixed_case(self):
    """Test encryption of mixed case."""
    result = encrypt("Hello World")
    assert result == "Svool Dliow"

  def test_encrypt_with_punctuation(self):
    """Test encryption preserves punctuation."""
    result = encrypt("HELLO, WORLD! 123")
    assert result == "SVOOL, DLIOW! 123"

  def test_encrypt_empty(self):
    """Test encryption of empty string."""
    result = encrypt("")
    assert result == ""

  def test_encrypt_no_letters(self):
    """Test encryption of string with no letters."""
    result = encrypt("123!@#")
    assert result == "123!@#"

  def test_encrypt_full_alphabet(self):
    """Test encryption of full alphabet."""
    result = encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    assert result == "ZYXWVUTSRQPONMLKJIHGFEDCBA"

  def test_encrypt_known_values(self):
    """Test encryption with known values."""
    assert encrypt("A") == "Z"
    assert encrypt("Z") == "A"
    assert encrypt("B") == "Y"
    assert encrypt("Y") == "B"
    assert encrypt("M") == "N"
    assert encrypt("N") == "M"


class TestAtbashDecrypt:
  """Test Atbash decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    result = decrypt("SVOOL")
    assert result == "HELLO"

  def test_decrypt_equals_encrypt(self):
    """Test that decrypt is same as encrypt (self-inverse)."""
    text = "HELLO WORLD"
    encrypted = encrypt(text)
    decrypted = decrypt(encrypted)
    assert decrypted == text

  def test_double_encrypt_equals_original(self):
    """Test that encrypting twice returns original."""
    text = "TEST MESSAGE"
    once = encrypt(text)
    twice = encrypt(once)
    assert twice == text


class TestAtbashHebrew:
  """Test Hebrew atbash encryption."""

  def test_encrypt_hebrew_basic(self):
    """Test basic Hebrew encryption."""
    # Hebrew letters: א (0x05D0) to ת (0x05EA)
    # Test with first letter א which should become ת
    aleph = chr(0x05D0)
    tav = chr(0x05EA)
    result = encrypt_hebrew(aleph)
    assert result == tav

  def test_encrypt_hebrew_reverse(self):
    """Test Hebrew reverse encryption."""
    tav = chr(0x05EA)
    aleph = chr(0x05D0)
    result = encrypt_hebrew(tav)
    assert result == aleph

  def test_encrypt_hebrew_preserves_non_hebrew(self):
    """Test Hebrew encryption preserves non-Hebrew chars."""
    result = encrypt_hebrew("123 ABC")
    assert result == "123 ABC"

  def test_encrypt_hebrew_word(self):
    """Test Hebrew word encryption."""
    # Testing with a sequence of Hebrew letters
    hebrew_text = chr(0x05D0) + chr(0x05D1) + chr(0x05D2)  # אבג
    result = encrypt_hebrew(hebrew_text)
    assert isinstance(result, str)
    assert len(result) == 3


class TestAtbashEdgeCases:
  """Test edge cases."""

  def test_single_letter(self):
    """Test single letter."""
    assert encrypt("A") == "Z"

  def test_palindrome_not_preserved(self):
    """Test that palindromes may not be preserved."""
    # "NOON" is a palindrome but encrypts to "MLLM"
    result = encrypt("NOON")
    assert result == "MLLM"

  def test_center_letters(self):
    """Test center letters M and N."""
    assert encrypt("M") == "N"
    assert encrypt("N") == "M"
