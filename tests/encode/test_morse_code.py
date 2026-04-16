"""Tests for Morse code encoding/decoding module."""

from __future__ import annotations

from crypt.encode.morse_code import (
  MORSE_CODE_DICT,
  REVERSE_MORSE_DICT,
  get_morse_timing,
  morse_decode,
  morse_decode_binary,
  morse_encode,
  morse_encode_binary,
  morse_validate,
)

import pytest


class TestMorseBasic:
  """Test basic Morse encoding/decoding."""

  def test_encode_single_letter(self):
    """Test encoding single letters."""
    assert morse_encode("A") == ".-"
    assert morse_encode("B") == "-..."
    assert morse_encode("E") == "."
    assert morse_encode("T") == "-"

  def test_encode_multiple_letters(self):
    """Test encoding multiple letters."""
    assert morse_encode("SOS") == "... --- ..."
    assert morse_encode("HELLO") == ".... . .-.. .-.. ---"

  def test_encode_word(self):
    """Test encoding a word."""
    assert morse_encode("HELLO WORLD") == ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."

  def test_encode_digits(self):
    """Test encoding digits."""
    assert morse_encode("123") == ".---- ..--- ...--"
    assert morse_encode("0") == "-----"

  def test_encode_punctuation(self):
    """Test encoding punctuation."""
    assert morse_encode(".") == ".-.-.-"
    assert morse_encode(",") == "--..--"
    assert morse_encode("?") == "..--.."

  def test_encode_empty(self):
    """Test encoding empty string."""
    assert morse_encode("") == ""

  def test_encode_lowercase(self):
    """Test that lowercase is handled correctly."""
    assert morse_encode("hello") == ".... . .-.. .-.. ---"
    assert morse_encode("sos") == "... --- ..."


class TestMorseDecode:
  """Test Morse code decoding."""

  def test_decode_single_letter(self):
    """Test decoding single letters."""
    assert morse_decode(".-") == "A"
    assert morse_decode("-...") == "B"
    assert morse_decode(".") == "E"
    assert morse_decode("-") == "T"

  def test_decode_multiple_letters(self):
    """Test decoding multiple letters."""
    assert morse_decode("... --- ...") == "SOS"
    assert morse_decode(".... . .-.. .-.. ---") == "HELLO"

  def test_decode_word(self):
    """Test decoding a word with word separator."""
    assert morse_decode(".... . .-.. .-.. --- / .-- --- .-. .-.. -..") == "HELLO WORLD"

  def test_decode_digits(self):
    """Test decoding digits."""
    assert morse_decode(".---- ..--- ...--") == "123"

  def test_decode_punctuation(self):
    """Test decoding punctuation."""
    assert morse_decode(".-.-.-") == "."
    assert morse_decode("--..--") == ","

  def test_decode_empty(self):
    """Test decoding empty string."""
    assert morse_decode("") == ""

  def test_decode_invalid_sequence(self):
    """Test decoding invalid Morse code."""
    with pytest.raises(ValueError, match="Invalid Morse code sequence"):
      morse_decode(".......")

  def test_decode_multiple_words(self):
    """Test decoding multiple words."""
    assert morse_decode(".- -... / -.-. -..") == "AB CD"

  def test_decode_empty_word_between_separators(self):
    """Test decoding with empty words between separators."""
    assert morse_decode(".- -... / / -.-. -..") == "AB CD"

  def test_decode_empty_char_between_separators(self):
    """Test decoding with empty chars between separators."""
    assert morse_decode(".-  -...") == "AB"

  def test_decode_all_empty_chars(self):
    """Test decoding where all chars are empty after stripping."""
    assert morse_decode("  /  ") == ""


class TestMorseRoundTrip:
  """Test encode/decode round-trips."""

  @pytest.mark.parametrize(
    "text",
    [
      "HELLO",
      "SOS",
      "HELLO WORLD",
      "TEST MESSAGE",
      "123",
      "ABC DEF GHI",
      "MORSE CODE",
    ],
  )
  def test_roundtrip_uppercase(self, text):
    """Test round-trip with uppercase text."""
    encoded = morse_encode(text)
    decoded = morse_decode(encoded)
    assert decoded == text

  @pytest.mark.parametrize(
    "text",
    [
      "hello",
      "sos",
      "Hello World",
      "TeSt MeSsAgE",
    ],
  )
  def test_roundtrip_mixed_case(self, text):
    """Test round-trip with mixed case (should return uppercase)."""
    encoded = morse_encode(text)
    decoded = morse_decode(encoded)
    assert decoded == text.upper()


class TestMorseBinary:
  """Test binary Morse encoding/decoding."""

  def test_encode_binary_single_letter(self):
    """Test binary encoding of single letters."""
    assert morse_encode_binary("E") == "1"
    assert morse_encode_binary("T") == "111"

  def test_encode_binary_sos(self):
    """Test binary encoding of SOS produces output."""
    result = morse_encode_binary("SOS")
    # Binary encoding produces a string with 1s and 0s
    assert isinstance(result, str)
    assert len(result) > 0
    assert all(c in "01" for c in result)

  def test_decode_binary_sos(self):
    """Test binary decoding of simple patterns."""
    # E = . = 1
    assert morse_decode_binary("1") == "E"
    # T = - = 111
    assert morse_decode_binary("111") == "T"

  def test_binary_roundtrip_simple(self):
    """Test binary encode/decode round-trip for simple text."""
    text = "E"
    binary = morse_encode_binary(text)
    decoded = morse_decode_binary(binary)
    assert decoded == text

  def test_encode_binary_empty(self):
    """Test binary encoding of empty string."""
    assert morse_encode_binary("") == ""

  def test_encode_binary_all_unsupported(self):
    """Test binary encoding of text with only unsupported chars."""
    assert morse_encode_binary("日本") == ""

  def test_decode_binary_empty(self):
    """Test binary decoding of empty string."""
    assert morse_decode_binary("") == ""

  def test_decode_binary_invalid(self):
    """Test binary decoding with invalid pattern."""
    with pytest.raises(ValueError, match="Invalid binary pattern"):
      morse_decode_binary("1010102")  # 2 is not valid

  def test_decode_binary_empty_word_between_gaps(self):
    """Test binary decoding with empty words between word gaps."""
    assert morse_decode_binary("1 0000000 1") == "E E"

  def test_decode_binary_invalid_symbol(self):
    """Test binary decoding with invalid symbol pattern."""
    with pytest.raises(ValueError, match="Invalid binary pattern"):
      morse_decode_binary("10102")


class TestMorseValidation:
  """Test Morse code validation."""

  def test_validate_valid_text(self):
    """Test validation of valid text."""
    assert morse_validate("HELLO") is True
    assert morse_validate("123") is True
    assert morse_validate("HELLO WORLD 123") is True

  def test_validate_invalid_text(self):
    """Test validation of invalid text."""
    assert morse_validate("café") is False  # é not supported
    assert morse_validate("naïve") is False  # ï not supported
    assert morse_validate("日本") is False  # Unicode not supported

  def test_validate_empty(self):
    """Test validation of empty string."""
    assert morse_validate("") is True  # Empty is technically valid

  def test_validate_non_string(self):
    """Test validation with non-string input."""
    assert morse_validate(123) is False
    assert morse_validate(None) is False


class TestMorseTiming:
  """Test Morse code timing calculations."""

  def test_timing_sos(self):
    """Test timing calculation for SOS."""
    timing = get_morse_timing("SOS")
    assert timing["total_symbols"] == 9  # 3 dots + 3 dashes + 3 dots
    assert timing["dot_ms"] == 50.0
    assert timing["dash_ms"] == 150.0
    assert timing["total_ms"] > 0

  def test_timing_empty(self):
    """Test timing calculation for empty string."""
    timing = get_morse_timing("")
    assert timing["total_symbols"] == 0
    assert timing["total_ms"] == 0.0

  def test_timing_custom_unit(self):
    """Test timing with custom unit duration."""
    timing = get_morse_timing("E", unit_ms=100.0)
    assert timing["dot_ms"] == 100.0
    assert timing["dash_ms"] == 300.0

  def test_timing_invalid_input(self):
    """Test timing with invalid input."""
    with pytest.raises(TypeError):
      get_morse_timing(123)


class TestMorseDict:
  """Test Morse code dictionaries."""

  def test_all_letters_present(self):
    """Test that all letters A-Z are in the dictionary."""
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
      assert letter in MORSE_CODE_DICT

  def test_all_digits_present(self):
    """Test that all digits 0-9 are in the dictionary."""
    for digit in "0123456789":
      assert digit in MORSE_CODE_DICT

  def test_reverse_dict_complete(self):
    """Test that reverse dictionary covers all codes."""
    for char, code in MORSE_CODE_DICT.items():
      if char != " ":  # Skip space
        assert code in REVERSE_MORSE_DICT


class TestMorseEdgeCases:
  """Test edge cases and error handling."""

  def test_encode_invalid_type(self):
    """Test encoding with invalid type."""
    with pytest.raises(TypeError, match="text must be a string"):
      morse_encode(123)
    with pytest.raises(TypeError, match="text must be a string"):
      morse_encode(None)

  def test_decode_invalid_type(self):
    """Test decoding with invalid type."""
    with pytest.raises(TypeError, match="encoded must be a string"):
      morse_decode(123)
    with pytest.raises(TypeError, match="encoded must be a string"):
      morse_decode(None)

  def test_encode_binary_invalid_type(self):
    """Test binary encoding with invalid type."""
    with pytest.raises(TypeError, match="text must be a string"):
      morse_encode_binary(123)

  def test_decode_binary_invalid_type(self):
    """Test binary decoding with invalid type."""
    with pytest.raises(TypeError, match="binary must be a string"):
      morse_decode_binary(123)

  def test_encode_with_unsupported_chars(self):
    """Test encoding with unsupported characters."""
    # Should skip unsupported characters (Japanese not supported)
    result = morse_encode("HELLO日本")
    # H E L L O (Japanese skipped)
    assert result == ".... . .-.. .-.. ---"

  def test_encode_skip_unsupported_chars(self):
    """Test that unsupported characters are skipped."""
    result = morse_encode("HELLO日本")
    # Japanese characters are not supported and should be skipped
    assert result == ".... . .-.. .-.. ---"

  def test_encode_all_unsupported_word(self):
    """Test encoding a word with only unsupported characters."""
    result = morse_encode("日本")
    assert result == ""

  def test_custom_separators(self):
    """Test encoding/decoding with custom separators."""
    encoded = morse_encode("HELLO", sep="  ", word_sep=" | ")
    assert "  " in encoded  # Double space between symbols
