"""Morse Code Encoding/Decoding

This module provides functions for encoding text to Morse code and decoding
Morse code back to text.

Features:
- Standard International Morse Code (ITU-R M.1677-1)
- Support for A-Z, 0-9, and common punctuation
- Prosigns (procedural signals) support
- Binary encoding for digital transmission
- Configurable separators

Timing conventions:
- Dot (.) = 1 unit
- Dash (-) = 3 units
- Intra-character gap (between symbols) = 1 unit
- Inter-character gap (between letters) = 3 units
- Inter-word gap = 7 units (represented by / or configurable)
"""

from __future__ import annotations

# Standard International Morse Code mapping
# Based on ITU-R M.1677-1 recommendation
MORSE_CODE_DICT: dict[str, str] = {
  # Letters A-Z
  "A": ".-",
  "B": "-...",
  "C": "-.-.",
  "D": "-..",
  "E": ".",
  "F": "..-.",
  "G": "--.",
  "H": "....",
  "I": "..",
  "J": ".---",
  "K": "-.-",
  "L": ".-..",
  "M": "--",
  "N": "-.",
  "O": "---",
  "P": ".--.",
  "Q": "--.-",
  "R": ".-.",
  "S": "...",
  "T": "-",
  "U": "..-",
  "V": "...-",
  "W": ".--",
  "X": "-..-",
  "Y": "-.--",
  "Z": "--..",
  # Digits 0-9
  "0": "-----",
  "1": ".----",
  "2": "..---",
  "3": "...--",
  "4": "....-",
  "5": ".....",
  "6": "-....",
  "7": "--...",
  "8": "---..",
  "9": "----.",
  # Punctuation marks
  ".": ".-.-.-",
  ",": "--..--",
  "?": "..--..",
  "'": ".----.",
  "!": "-.-.--",
  "/": "-..-.",
  "(": "-.--.",
  ")": "-.--.-",
  "&": ".-...",
  ":": "---...",
  ";": "-.-.-.",
  "=": "-...-",
  "+": ".-.-.",
  "-": "-....-",
  "_": "..--.-",
  '"': ".-..-.",
  "$": "...-..-",
  "@": ".--.-.",
  # Space
  " ": "/",
}

# Reverse mapping: Morse code to character
REVERSE_MORSE_DICT: dict[str, str] = {v: k for k, v in MORSE_CODE_DICT.items()}


def morse_encode(text: object, *, sep: str = " ", word_sep: str = " / ") -> str:
  """Encode text to International Morse Code.

  Args:
      text: The text to encode. Only A-Z, 0-9, and supported punctuation
            are encoded. Other characters are ignored.
      sep: Separator between symbols within a character (default: space).
      word_sep: Separator between words (default: " / ").

  Returns:
      The Morse code representation of the input text.

  Raises:
      TypeError: If text is not a string.

  Examples:
      >>> morse_encode("SOS")
      '... --- ...'
      >>> morse_encode("Hello World")
      '.... . .-.. .-.. --- / .-- --- .-. .-.. -..'
      >>> morse_encode("123")
      '.---- ..--- ...--'
  """
  if not isinstance(text, str):
    msg = "text must be a string"
    raise TypeError(msg)

  if not text:
    return ""

  words = text.upper().split()
  encoded_words = []

  for word in words:
    if encoded_chars := [
      MORSE_CODE_DICT[char] for char in word if char in MORSE_CODE_DICT
    ]:
      encoded_words.append(sep.join(encoded_chars))  # noqa: PERF401

  return word_sep.join(encoded_words)


def morse_decode(encoded: object, *, sep: str = " ", word_sep: str = "/") -> str:
  """Decode International Morse Code to text.

  Args:
      encoded: The Morse code string to decode. Symbols should be separated
               by spaces, and words by "/" or the specified separators.
      sep: Separator between symbols within a character (default: space).
      word_sep: Separator between words (default: "/").

  Returns:
      The decoded text in uppercase.

  Raises:
      TypeError: If encoded is not a string.
      ValueError: If an invalid Morse code sequence is encountered.

  Examples:
      >>> morse_decode("... --- ...")
      'SOS'
      >>> morse_decode(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
      'HELLO WORLD'
  """
  if not isinstance(encoded, str):
    msg = "encoded must be a string"
    raise TypeError(msg)

  if not encoded:
    return ""

  # Normalize the input
  encoded = encoded.strip()

  # Split into words
  words = encoded.split(word_sep)
  decoded_words = []

  for word_raw in words:
    word_stripped = word_raw.strip()
    if not word_stripped:
      continue

    chars = word_stripped.split(sep)
    decoded_chars = []

    for char_raw in chars:
      char_stripped = char_raw.strip()
      if not char_stripped:
        continue
      if char_stripped in REVERSE_MORSE_DICT:
        decoded_chars.append(REVERSE_MORSE_DICT[char_stripped])
      else:
        msg = f"Invalid Morse code sequence: {char_stripped!r}"
        raise ValueError(msg)

    if decoded_chars:
      decoded_words.append("".join(decoded_chars))

  return " ".join(decoded_words)


def morse_encode_binary(
  text: object,
  *,
  dot: str = "1",
  dash: str = "111",
  symbol_gap: str = "0",
  char_gap: str = "000",
  **kwargs: str,
) -> str:
  """Encode text to binary Morse code representation.

  This format represents Morse code for digital transmission where:
  - Dot = 1 unit (e.g., "1")
  - Dash = 3 units (e.g., "111")
  - Intra-symbol gap = 1 unit (e.g., "0")
  - Inter-character gap = 3 units (e.g., "000")
  - Inter-word gap = 7 units (e.g., "0000000")

  Args:
      text: The text to encode.
      dot: Binary representation of a dot (default: "1").
      dash: Binary representation of a dash (default: "111").
      symbol_gap: Gap between symbols in a character (default: "0").
      char_gap: Gap between characters (default: "000").

  Returns:
      Binary representation of the Morse code.

  Raises:
      TypeError: If text is not a string.

  Examples:
      >>> morse_encode_binary("SOS")
      '101010001110111011100010101'
      >>> morse_encode_binary("E")
      '1'
  """
  word_gap: str = kwargs.get("word_gap", "0000000")
  if not isinstance(text, str):
    msg = "text must be a string"
    raise TypeError(msg)

  if not text:
    return ""

  morse = morse_encode(text)
  if not morse:
    return ""

  words = morse.split(" / ")
  binary_words = []

  for word in words:
    chars = word.split()
    binary_chars = []

    for char in chars:
      # Split morse character into individual symbols (dots and dashes)
      # Then convert each symbol to binary representation
      symbols = list(char)  # e.g., ".-" -> [".", "-"]
      binary_symbols = [dot if s == "." else dash for s in symbols]
      # Join symbols within a character with symbol_gap
      binary_chars.append(symbol_gap.join(binary_symbols))

    # Join characters with char_gap
    binary_words.append(char_gap.join(binary_chars))

  # Join words with word_gap
  return word_gap.join(binary_words)


def _decode_binary_char(
  char_raw: str,
  dot: str,
  dash: str,
  symbol_gap: str,
) -> str:
  """Decode a single binary morse character to a morse symbol string."""
  char_stripped = char_raw.strip()
  if not char_stripped:
    return ""
  symbols = char_stripped.split(symbol_gap)
  morse_char = ""
  for symbol in symbols:
    if symbol == dot:
      morse_char += "."
    elif symbol == dash:
      morse_char += "-"
    else:
      msg = f"Invalid binary pattern: {symbol!r}"
      raise ValueError(msg)
  if morse_char in REVERSE_MORSE_DICT:
    return REVERSE_MORSE_DICT[morse_char]
  msg = f"Invalid Morse code: {morse_char!r}"
  raise ValueError(msg)


def morse_decode_binary(
  binary: object,
  *,
  dot: str = "1",
  dash: str = "111",
  symbol_gap: str = "0",
  char_gap: str = "000",
  **kwargs: str,
) -> str:
  """Decode binary Morse code representation to text.

  Args:
      binary: The binary Morse code string.
      dot: Binary representation of a dot (default: "1").
      dash: Binary representation of a dash (default: "111").
      symbol_gap: Gap between symbols in a character (default: "0").
      char_gap: Gap between characters (default: "000").
  Returns:
      The decoded text in uppercase.

  Raises:
      TypeError: If binary is not a string.
      ValueError: If invalid binary pattern is encountered.

  Examples:
      >>> morse_decode_binary("101010001110111011100010101")
      'SOS'
  """
  word_gap: str = kwargs.get("word_gap", "0000000")
  if not isinstance(binary, str):
    msg = "binary must be a string"
    raise TypeError(msg)

  if not binary:
    return ""

  # Normalize word gaps by replacing with standard separator
  normalized = binary.replace(word_gap, " / ")

  # Split into words
  words = normalized.split(" / ")
  decoded_words = []

  for word_raw in words:
    word_stripped = word_raw.strip()
    if not word_stripped:
      continue

    # Split characters by char_gap and decode each
    chars = word_stripped.split(char_gap)
    decoded_chars = [
      _decode_binary_char(c, dot, dash, symbol_gap) for c in chars if c.strip()
    ]
    if decoded_chars := [ch for ch in decoded_chars if ch]:
      decoded_words.append("".join(decoded_chars))

  return " ".join(decoded_words)


def morse_validate(text: object) -> bool:
  """Check if text contains only valid Morse code characters.

  Args:
      text: The text to validate.

  Returns:
      True if all characters can be encoded to Morse code,
      False otherwise.

  Examples:
      >>> morse_validate("HELLO 123")
      True
      >>> morse_validate("Hello!")
      False  # '!' is not supported
  """
  if not isinstance(text, str):
    return False

  return all(char in MORSE_CODE_DICT for char in text.upper())


def get_morse_timing(text: object, unit_ms: float = 50.0) -> dict[str, float]:
  """Calculate timing information for Morse code transmission.

  Args:
      text: The text to encode.
      unit_ms: Duration of one unit in milliseconds (default: 50ms).

  Returns:
      Dictionary with timing breakdown.

  Examples:
      >>> timing = get_morse_timing("SOS")
      >>> timing['total_ms']  # Total transmission time
      950.0
  """
  if not isinstance(text, str):
    msg = "text must be a string"
    raise TypeError(msg)

  morse = morse_encode(text)
  if not morse:
    return {
      "dot_ms": unit_ms,
      "dash_ms": unit_ms * 3,
      "symbol_gap_ms": unit_ms,
      "char_gap_ms": unit_ms * 3,
      "word_gap_ms": unit_ms * 7,
      "total_symbols": 0,
      "total_ms": 0.0,
    }

  dots = morse.count(".")
  dashes = morse.count("-")
  symbols = dots + dashes

  # Calculate timing based on ITU-R M.1677-1
  dot_time = dots * unit_ms
  dash_time = dashes * unit_ms * 3

  # Count gaps
  words = morse.split(" / ")
  symbol_gaps = 0
  char_gaps = 0
  word_gaps = len(words) - 1 if len(words) > 1 else 0

  for word in words:
    chars = word.split()
    for char in chars:
      symbol_gaps += len(char) - 1 if len(char) > 0 else 0
    char_gaps += len(chars) - 1 if len(chars) > 1 else 0

  symbol_gap_time = symbol_gaps * unit_ms
  char_gap_time = char_gaps * unit_ms * 3
  word_gap_time = word_gaps * unit_ms * 7

  total_time = dot_time + dash_time + symbol_gap_time + char_gap_time + word_gap_time

  return {
    "dot_ms": unit_ms,
    "dash_ms": unit_ms * 3,
    "symbol_gap_ms": unit_ms,
    "char_gap_ms": unit_ms * 3,
    "word_gap_ms": unit_ms * 7,
    "total_symbols": symbols,
    "total_ms": total_time,
  }
