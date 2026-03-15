# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_affine_cipher.py
# @time    : 2026/3/15
# @desc    : Tests for Affine cipher encryption/decryption

from crypt.encrypt.symmetric_encrypt.substitution import affine_cipher

import pytest


class TestAffineEncrypt:
  """Test Affine cipher encryption."""

  def test_encrypt_basic(self):
    """Test basic encryption."""
    # E(x) = (5x + 8) mod 26
    # H(7) -> (5*7 + 8) = 43 mod 26 = 17 -> R
    result = affine_cipher.encrypt("H", 5, 8)
    assert result == "R"

  def test_encrypt_hello(self):
    """Test encryption of HELLO."""
    result = affine_cipher.encrypt("HELLO", 5, 8)
    assert result == "RCLLA"

  def test_encrypt_lowercase(self):
    """Test encryption converts to uppercase."""
    result = affine_cipher.encrypt("hello", 5, 8)
    assert result == "RCLLA"

  def test_encrypt_mixed_case(self):
    """Test encryption with mixed case."""
    result = affine_cipher.encrypt("HeLLo", 5, 8)
    assert result == "RCLLA"

  def test_encrypt_preserves_non_alpha(self):
    """Test encryption preserves non-alphabetic characters."""
    result = affine_cipher.encrypt("HELLO, WORLD!", 5, 8)
    assert result == "RCLLA, OAPLX!"

  def test_encrypt_empty_string(self):
    """Test encryption of empty string."""
    assert affine_cipher.encrypt("", 5, 8) == ""

  def test_encrypt_single_char(self):
    """Test encryption of single characters."""
    # With a=1, b=3, this is equivalent to Caesar shift 3
    assert affine_cipher.encrypt("A", 1, 3) == "D"
    assert affine_cipher.encrypt("Z", 1, 3) == "C"

  def test_encrypt_with_different_keys(self):
    """Test encryption with various valid keys."""
    test_cases = [
      ((3, 5), "ABC", "FIL"),    # A->F, B->I, C->L
      ((5, 10), "TEST", "BEWB"),  # T->B, E->P, S->L, T->B
      ((7, 15), "HELLO", "MROOJ"),  # H->M, E->R, L->O, L->O, O->J
    ]
    for (a, b), plaintext, expected in test_cases:
      result = affine_cipher.encrypt(plaintext, a, b)
      assert result == expected, f"Failed for keys ({a}, {b}): got {result}, expected {expected}"

  def test_encrypt_all_letters(self):
    """Test encryption of all letters."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # With a=1, b=1, this is Caesar shift 1
    result = affine_cipher.encrypt(alphabet, 1, 1)
    assert result == "BCDEFGHIJKLMNOPQRSTUVWXYZA"


class TestAffineDecrypt:
  """Test Affine cipher decryption."""

  def test_decrypt_basic(self):
    """Test basic decryption."""
    result = affine_cipher.decrypt("R", 5, 8)
    assert result == "H"

  def test_decrypt_hello(self):
    """Test decryption of encrypted HELLO."""
    encrypted = affine_cipher.encrypt("HELLO", 5, 8)
    result = affine_cipher.decrypt(encrypted, 5, 8)
    assert result == "HELLO"

  def test_decrypt_preserves_non_alpha(self):
    """Test decryption preserves non-alphabetic characters."""
    result = affine_cipher.decrypt("RCLLA, OAPLX!", 5, 8)
    assert result == "HELLO, WORLD!"

  def test_decrypt_empty_string(self):
    """Test decryption of empty string."""
    assert affine_cipher.decrypt("", 5, 8) == ""


class TestAffineRoundtrip:
  """Test encryption/decryption roundtrip."""

  @pytest.mark.parametrize(
    ("text", "a", "b"),
    [
      ("HELLO", 5, 8),
      ("hello", 3, 7),
      ("Hello World", 9, 12),
      ("ABC123!", 11, 5),
      ("", 5, 10),
      ("A", 17, 3),
      ("THE QUICK BROWN FOX", 7, 15),
    ],
  )
  def test_roundtrip(self, text, a, b):
    """Test that decrypt(encrypt(text)) == text."""
    encrypted = affine_cipher.encrypt(text, a, b)
    decrypted = affine_cipher.decrypt(encrypted, a, b)
    assert decrypted == text.upper()


class TestAffineInvalidKeys:
  """Test handling of invalid keys."""

  def test_encrypt_invalid_a_not_coprime(self):
    """Test encryption fails when a is not coprime with 26."""
    with pytest.raises(ValueError, match="互质"):
      affine_cipher.encrypt("HELLO", 2, 5)  # 2 and 26 share factor 2

  def test_encrypt_invalid_a_zero(self):
    """Test encryption fails when a is 0."""
    with pytest.raises(ValueError, match="互质"):
      affine_cipher.encrypt("HELLO", 0, 5)

  def test_encrypt_invalid_a_13(self):
    """Test encryption fails when a is 13."""
    with pytest.raises(ValueError, match="互质"):
      affine_cipher.encrypt("HELLO", 13, 5)  # 13 and 26 share factor 13

  def test_decrypt_invalid_a(self):
    """Test decryption fails when a has no modular inverse."""
    with pytest.raises(ValueError, match="逆元"):
      affine_cipher.decrypt("HELLO", 2, 5)

  def test_encrypt_a_26_multiple(self):
    """Test encryption fails when a shares factor with 26."""
    invalid_values = [2, 4, 6, 8, 10, 12, 13, 14, 16, 18, 20, 22, 24]
    for a in invalid_values:
      with pytest.raises(ValueError):
        affine_cipher.encrypt("A", a, 1)


class TestAffineValidAValues:
  """Test valid values for a (coprime with 26)."""

  def test_get_valid_a_values(self):
    """Test getting valid a values."""
    valid = affine_cipher.get_valid_a_values()
    # Values coprime with 26: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
    expected = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    assert valid == expected

  def test_all_valid_a_values_work(self):
    """Test that all valid a values work for encryption/decryption."""
    valid = affine_cipher.get_valid_a_values()
    text = "TEST"

    for a in valid:
      encrypted = affine_cipher.encrypt(text, a, 5)
      decrypted = affine_cipher.decrypt(encrypted, a, 5)
      assert decrypted == text


class TestAffineBruteForce:
  """Test Affine cipher brute force decryption."""

  def test_brute_force_decrypt(self):
    """Test brute force returns correct keys."""
    original = "HELLO"
    encrypted = affine_cipher.encrypt(original, 5, 8)
    results = affine_cipher.brute_force_decrypt(encrypted)

    # Find the correct result
    correct_result = next((r for r in results if r["text"] == original), None)
    assert correct_result is not None
    assert correct_result["a"] == 5
    assert correct_result["b"] == 8

  def test_brute_force_returns_all_combinations(self):
    """Test brute force returns all valid (a, b) combinations."""
    results = affine_cipher.brute_force_decrypt("A")
    # 12 valid a values * 26 b values = 312 combinations
    assert len(results) == 312

  def test_brute_force_result_format(self):
    """Test brute force result format."""
    results = affine_cipher.brute_force_decrypt("TEST")
    for result in results:
      assert "a" in result
      assert "b" in result
      assert "text" in result
      assert isinstance(result["a"], int)
      assert isinstance(result["b"], int)
      assert isinstance(result["text"], str)


class TestAffineEdgeCases:
  """Test edge cases."""

  def test_encrypt_non_alpha_only(self):
    """Test encryption of string with no letters."""
    assert affine_cipher.encrypt("12345!@#$%", 5, 8) == "12345!@#$%"

  def test_encrypt_unicode(self):
    """Test encryption with unicode characters."""
    # Unicode characters should be preserved (only ASCII letters are encrypted)
    result = affine_cipher.encrypt("Héllo", 5, 8)
    assert result == "RéLLA"

  def test_b_value_range(self):
    """Test b value can be any integer 0-25."""
    text = "A"
    for b in range(26):
      result = affine_cipher.encrypt(text, 5, b)
      # Just verify it doesn't raise an error
      assert len(result) == 1

  def test_large_b_value(self):
    """Test b value larger than 26."""
    # b should be taken mod 26
    result1 = affine_cipher.encrypt("A", 5, 8)
    result2 = affine_cipher.encrypt("A", 5, 34)  # 34 % 26 = 8
    assert result1 == result2


class TestAffineMathematicalProperties:
  """Test mathematical properties of Affine cipher."""

  def test_identity_key(self):
    """Test a=1, b=0 is identity transformation."""
    text = "HELLO WORLD"
    result = affine_cipher.encrypt(text, 1, 0)
    assert result == text

  def test_caesar_equivalence(self):
    """Test a=1 is equivalent to Caesar cipher."""
    text = "HELLO"
    shift = 5

    affine_result = affine_cipher.encrypt(text, 1, shift)
    # This should match Caesar with shift 5
    # Caesar: H->M, E->J, L->Q, L->Q, O->T
    assert affine_result == "MJQQT"

  def test_composition_not_commutative(self):
    """Test that key composition is not commutative."""
    text = "A"
    # (a=3,b=5) then (a=5,b=7) is different from (a=5,b=7) then (a=3,b=5)
    first = affine_cipher.encrypt(text, 3, 5)
    composed1 = affine_cipher.encrypt(first, 5, 7)

    first = affine_cipher.encrypt(text, 5, 7)
    composed2 = affine_cipher.encrypt(first, 3, 5)

    assert composed1 != composed2
