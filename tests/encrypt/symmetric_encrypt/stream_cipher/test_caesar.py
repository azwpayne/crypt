"""Tests for Caesar cipher implementation."""

from crypt.encrypt.symmetric_encrypt.stream_cipher.caesar import (
  brute_force_decrypt,
  decrypt,
  decrypt_with_custom_alphabet,
  encrypt,
  encrypt_with_custom_alphabet,
)


class TestCaesarEncrypt:
  """Test Caesar encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption."""
    result = encrypt("HELLO", 3)
    assert result == "KHOOR"

  def test_encrypt_shift_13(self):
    """Test ROT13 encryption."""
    result = encrypt("HELLO", 13)
    assert result == "URYYB"

  def test_encrypt_shift_26(self):
    """Test shift of 26 (full rotation)."""
    result = encrypt("HELLO", 26)
    assert result == "HELLO"

  def test_encrypt_shift_0(self):
    """Test shift of 0 (no change)."""
    result = encrypt("HELLO", 0)
    assert result == "HELLO"

  def test_encrypt_lowercase(self):
    """Test encryption of lowercase."""
    result = encrypt("hello", 3)
    assert result == "khoor"

  def test_encrypt_mixed_case(self):
    """Test encryption of mixed case."""
    result = encrypt("Hello World", 3)
    assert result == "Khoor Zruog"

  def test_encrypt_with_punctuation(self):
    """Test encryption preserves punctuation."""
    result = encrypt("HELLO, WORLD! 123", 3)
    assert result == "KHOOR, ZRUOG! 123"

  def test_encrypt_empty(self):
    """Test encryption of empty string."""
    result = encrypt("", 3)
    assert result == ""

  def test_encrypt_negative_shift(self):
    """Test encryption with negative shift."""
    result = encrypt("HELLO", -3)
    assert result == "EBIIL"


class TestCaesarDecrypt:
  """Test Caesar decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    result = decrypt("KHOOR", 3)
    assert result == "HELLO"

  def test_decrypt_roundtrip(self):
    """Test encrypt/decrypt roundtrip."""
    original = "ATTACKATDAWN"
    encrypted = encrypt(original, 7)
    decrypted = decrypt(encrypted, 7)
    assert decrypted == original

  def test_decrypt_rot13(self):
    """Test ROT13 decryption (same as encryption)."""
    encrypted = "URYYB"
    decrypted = decrypt(encrypted, 13)
    assert decrypted == "HELLO"


class TestCustomAlphabet:
  """Test custom alphabet functions."""

  def test_custom_alphabet_basic(self):
    """Test encryption with custom alphabet."""
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    result = encrypt_with_custom_alphabet("hello", 3, alphabet)
    assert result == "khoor"

  def test_custom_alphabet_roundtrip(self):
    """Test custom alphabet roundtrip."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    original = "HELLO"
    encrypted = encrypt_with_custom_alphabet(original, 5, alphabet)
    decrypted = decrypt_with_custom_alphabet(encrypted, 5, alphabet)
    assert decrypted == original

  def test_custom_alphabet_reversed(self):
    """Test with reversed alphabet."""
    alphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
    result = encrypt_with_custom_alphabet("ZYX", 1, alphabet)
    # Z(0)+1=Y, Y(1)+1=X, X(2)+1=W -> "YXW"
    assert result == "YXW"

  def test_custom_alphabet_preserves_other_chars(self):
    """Test custom alphabet preserves chars not in alphabet."""
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    result = encrypt_with_custom_alphabet("hello, world!", 3, alphabet)
    assert result == "khoor, zruog!"


class TestBruteForce:
  """Test brute force decryption."""

  def test_brute_force_returns_all_shifts(self):
    """Test brute force returns all possible shifts."""
    encrypted = "khoor"
    results = brute_force_decrypt(encrypted)
    assert len(results) == 26
    assert 0 in results
    assert 25 in results

  def test_brute_force_contains_original(self):
    """Test brute force results contain original plaintext."""
    original = "hello"
    encrypted = encrypt_with_custom_alphabet(original, 3)
    results = brute_force_decrypt(encrypted)
    assert results[3] == original  # Shift 3 should decrypt correctly


class TestCaesarEdgeCases:
  """Test edge cases."""

  def test_large_shift(self):
    """Test encryption with large shift value."""
    result = encrypt("HELLO", 29)  # 29 % 26 = 3
    assert result == "KHOOR"

  def test_large_negative_shift(self):
    """Test encryption with large negative shift."""
    result = encrypt("HELLO", -29)  # -29 % 26 = -3
    assert result == "EBIIL"

  def test_single_letter(self):
    """Test encryption of single letter."""
    assert encrypt("A", 1) == "B"
    assert encrypt("Z", 1) == "A"
    assert encrypt("A", -1) == "Z"

  def test_no_letters(self):
    """Test encryption of string with no letters."""
    result = encrypt("123!@#", 3)
    assert result == "123!@#"
