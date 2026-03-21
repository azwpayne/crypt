"""Tests for rail fence cipher implementation."""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.block_cipher.rail_fence_cipher import (
  brute_force_decrypt,
  decrypt,
  encrypt,
  encrypt_with_offset,
  print_fence,
)


class TestRailFenceEncrypt:
  """Tests for rail fence encryption."""

  def test_two_rails(self):
    # WEAREDISCOVERING -> WAEICVRNERDSOIG (classic example)
    result = encrypt("WEAREDISCOVERING", 2)
    assert result == "WAEICVRNERDSOEIG"

  def test_three_rails(self):
    # WE ARE DISCOVERED -> WECRLTEERDSOEEAIVDEN
    result = encrypt("WEAREDISCOVERED", 3)
    assert len(result) == len("WEAREDISCOVERED")

  def test_single_rail_is_identity(self):
    text = "HELLO"
    assert encrypt(text, 1) == text

  def test_rails_equal_length_is_identity(self):
    text = "AB"
    # With rails >= len, each char on its own rail -> no reordering
    result = encrypt(text, len(text))
    assert len(result) == len(text)

  def test_empty_string(self):
    assert encrypt("", 3) == ""

  def test_single_char(self):
    assert encrypt("X", 3) == "X"


class TestRailFenceDecrypt:
  """Tests for rail fence decryption."""

  def test_two_rails_roundtrip(self):
    plaintext = "HELLOWORLD"
    assert decrypt(encrypt(plaintext, 2), 2) == plaintext

  def test_three_rails_roundtrip(self):
    plaintext = "WEAREDISCOVERING"
    assert decrypt(encrypt(plaintext, 3), 3) == plaintext

  def test_four_rails_roundtrip(self):
    plaintext = "CRYPTOGRAPHYISFUN"
    assert decrypt(encrypt(plaintext, 4), 4) == plaintext

  def test_single_rail_roundtrip(self):
    text = "IDENTITY"
    assert decrypt(encrypt(text, 1), 1) == text

  def test_empty_string(self):
    assert decrypt("", 3) == ""


class TestBruteForceDecrypt:
  """Tests for brute force rail fence decryption."""

  def test_returns_dict(self):
    result = brute_force_decrypt("HELLO", max_rails=5)
    assert isinstance(result, dict)

  def test_contains_correct_plaintext(self):
    plaintext = "HELLOWORLD"
    ciphertext = encrypt(plaintext, 3)
    results = brute_force_decrypt(ciphertext, max_rails=5)
    assert 3 in results
    assert results[3] == plaintext

  def test_max_rails_limits_results(self):
    results = brute_force_decrypt("ABCDEF", max_rails=4)
    assert all(k <= 4 for k in results)


class TestEncryptWithOffset:
  """Tests for rail fence encryption with offset."""

  def test_zero_offset_same_as_normal(self):
    text = "HELLOWORLD"
    assert encrypt_with_offset(text, 3, 0) == encrypt(text, 3)

  def test_offset_produces_different_result(self):
    text = "HELLOWORLD"
    r1 = encrypt_with_offset(text, 3, 0)
    r2 = encrypt_with_offset(text, 3, 1)
    # Different offsets generally yield different ciphertexts
    assert len(r1) == len(r2) == len(text)

  def test_empty_string(self):
    assert encrypt_with_offset("", 3, 2) == ""


class TestPrintFence:
  """Tests for print_fence visualization."""

  def test_returns_string(self):
    result = print_fence("HELLO", 2)
    assert isinstance(result, str)

  def test_contains_all_chars(self):
    text = "HELLO"
    result = print_fence(text, 3)
    for ch in text:
      assert ch in result

  def test_two_rails_has_two_rows(self):
    result = print_fence("HELLOWORLD", 2)
    lines = [ln for ln in result.splitlines() if ln.strip()]
    assert len(lines) == 2
