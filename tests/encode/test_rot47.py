"""Tests for ROT-47 and ROT-13 encoding."""

from crypt.encode.rot47 import rot13, rot47


class TestROT47:
  def test_involution(self):
    text = "Hello, World! 123"
    assert rot47(rot47(text)) == text

  def test_known_vector(self):
    # '!' (33) rotated 47 -> 'P' (80)
    assert rot47("!") == "P"

  def test_non_printable_unchanged(self):
    assert rot47("\t\n") == "\t\n"

  def test_space_unchanged(self):
    # space (32) is below the 33-126 range
    assert rot47(" ") == " "


class TestROT13:
  def test_involution(self):
    assert rot13(rot13("Hello, World!")) == "Hello, World!"

  def test_known_vector(self):
    assert rot13("abc") == "nop"
    assert rot13("ABC") == "NOP"

  def test_non_alpha_unchanged(self):
    assert rot13("123!@#") == "123!@#"

  def test_case_preserved(self):
    result = rot13("Hello")
    assert result[0].isupper()
    assert result[1:].islower()
