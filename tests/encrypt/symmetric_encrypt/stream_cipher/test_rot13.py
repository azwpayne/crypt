"""Tests for ROT13 cipher implementation."""

from crypt.encrypt.symmetric_encrypt.stream_cipher.rot13 import (
  _create_rot13_table,
  decrypt,
  encrypt,
)


class TestCreateRot13Table:
  """Test ROT13 table creation."""

  def test_create_table(self):
    """Test that translation table is created."""
    table = _create_rot13_table()
    assert isinstance(table, dict)


class TestRot13Encrypt:
  """Test ROT13 encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption."""
    result = encrypt("HELLO")
    assert result == "URYYB"

  def test_encrypt_lowercase(self):
    """Test encryption of lowercase."""
    result = encrypt("hello")
    assert result == "uryyb"

  def test_encrypt_mixed_case(self):
    """Test encryption of mixed case."""
    result = encrypt("Hello World")
    assert result == "Uryyb Jbeyq"

  def test_encrypt_with_punctuation(self):
    """Test encryption preserves punctuation."""
    result = encrypt("HELLO, WORLD! 123")
    assert result == "URYYB, JBEYQ! 123"

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
    assert result == "NOPQRSTUVWXYZABCDEFGHIJKLM"

  def test_encrypt_known_values(self):
    """Test encryption with known values."""
    assert encrypt("A") == "N"
    assert encrypt("N") == "A"
    assert encrypt("B") == "O"
    assert encrypt("O") == "B"
    assert encrypt("M") == "Z"
    assert encrypt("Z") == "M"


class TestRot13Decrypt:
  """Test ROT13 decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    result = decrypt("URYYB")
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


class TestRot13EdgeCases:
  """Test edge cases."""

  def test_single_letter(self):
    """Test single letter."""
    assert encrypt("A") == "N"
    assert encrypt("N") == "A"

  def test_center_letters(self):
    """Test center letters M and N."""
    assert encrypt("M") == "Z"
    assert encrypt("N") == "A"
