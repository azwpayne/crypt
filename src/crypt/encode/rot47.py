"""ROT-47 and ROT-13 substitution ciphers — pure Python implementation.

ROT-47 rotates all printable ASCII characters (! through ~, codes 33-126).
ROT-13 rotates only ASCII letters (a-z, A-Z).
Both are involutions: applying twice returns the original text.
"""


def rot47(text: str) -> str:
  """Apply ROT-47 to *text*.

  Characters in the printable ASCII range 33-126 are rotated by 47.
  All other characters (spaces, control chars, non-ASCII) are unchanged.
  """
  result = []
  for ch in text:
    code = ord(ch)
    if 33 <= code <= 126:
      result.append(chr(33 + (code - 33 + 47) % 94))
    else:
      result.append(ch)
  return "".join(result)


def rot13(text: str) -> str:
  """Apply ROT-13 to *text*.

  Only ASCII letters are rotated; all other characters are unchanged.
  """
  result = []
  for ch in text:
    if "a" <= ch <= "z":
      result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
    elif "A" <= ch <= "Z":
      result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
    else:
      result.append(ch)
  return "".join(result)
