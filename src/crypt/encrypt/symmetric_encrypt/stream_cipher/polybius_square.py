"""Polybius square cipher implementation."""


def _create_square(
  key: str = "", size: int = 5
) -> tuple[list[list[str]], str, dict[str, tuple[int, int]]]:
  """Create a Polybius square and character position map.

  Args:
      key: Key used to fill the first positions of the square.
      size: Square size (5x5 or 6x6).

  Returns:
      A tuple of (square, alphabet, position_map).
  """
  if size == 5:
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is merged with I
  elif size == 6:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  else:
    msg = "方阵大小必须是5或6"
    raise ValueError(msg)

  seen = set()
  unique_key = []
  for c in key.upper():
    char_to_add = c
    if char_to_add == "J" and size == 5:
      char_to_add = "I"
    if char_to_add not in seen and char_to_add in alphabet:
      seen.add(char_to_add)
      unique_key.append(char_to_add)

  remaining = [c for c in alphabet if c not in seen]
  full_sequence = unique_key + remaining

  square = [full_sequence[i * size : (i + 1) * size] for i in range(size)]

  position_map = {
    char: (row_idx, col_idx)
    for row_idx, row in enumerate(square)
    for col_idx, char in enumerate(row)
  }

  return square, alphabet, position_map


def encrypt(  # noqa: PLR0913
  text: str,
  key: str = "",
  size: int = 5,
  row_labels: str = "",
  col_labels: str = "",
  *,
  strict: bool = False,
) -> str:
  """Encrypt text using a Polybius square.

  Args:
      text: Plaintext to encrypt.
      key: Optional key to customize the square.
      size: Square size (5 or 6).
      row_labels: Row labels (defaults to 1,2,3,...).
      col_labels: Column labels (defaults to 1,2,3,...).
      strict: If True, raise ValueError for characters not in the alphabet.

  Returns:
      Encrypted coordinate string.

  Example:
      >>> encrypt("HELLO")
      '23 15 31 31 34'
  """
  _, alphabet, position_map = _create_square(key, size)

  if not row_labels:
    row_labels = "".join(str(i + 1) for i in range(size))
  if not col_labels:
    col_labels = "".join(str(i + 1) for i in range(size))

  result = []
  for char in text.upper():
    processed_char = char
    if processed_char == "J" and size == 5:
      processed_char = "I"

    if processed_char not in alphabet:
      if strict:
        msg = f"Character {char!r} cannot be encoded with the current Polybius square"
        raise ValueError(msg)
      continue

    row, col = position_map[processed_char]
    result.append(f"{row_labels[row]}{col_labels[col]}")

  return " ".join(result)


def decrypt(  # noqa: PLR0913
  encrypted_text: str,
  key: str = "",
  size: int = 5,
  row_labels: str = "",
  col_labels: str = "",
  *,
  strict: bool = False,
) -> str:
  """Decrypt text using a Polybius square.

  Args:
      encrypted_text: Coordinate string to decrypt.
      key: Optional key.
      size: Square size.
      row_labels: Row labels.
      col_labels: Column labels.
      strict: If True, raise ValueError for invalid input.

  Returns:
      Decrypted string.
  """
  square, _, _ = _create_square(key, size)

  if not row_labels:
    row_labels = "".join(str(i + 1) for i in range(size))
  if not col_labels:
    col_labels = "".join(str(i + 1) for i in range(size))

  row_map = {c: i for i, c in enumerate(row_labels)}
  col_map = {c: i for i, c in enumerate(col_labels)}

  result = []
  codes = encrypted_text.replace(" ", "")

  if strict and len(codes) % 2 != 0:
    msg = "Invalid encrypted text length (must be even number of coordinate characters)"
    raise ValueError(msg)

  for i in range(0, len(codes) - 1, 2):
    row_char = codes[i]
    col_char = codes[i + 1]

    if row_char not in row_map or col_char not in col_map:
      if strict:
        msg = f"Invalid coordinate pair: {row_char!r}{col_char!r}"
        raise ValueError(msg)
      continue

    row = row_map[row_char]
    col = col_map[col_char]
    result.append(square[row][col])

  return "".join(result)


def print_square(key: str = "", size: int = 5) -> str:
  """Print a formatted Polybius square.

  Args:
      key: Optional key.
      size: Square size.

  Returns:
      Formatted square string.
  """
  square, _, _ = _create_square(key, size)

  lines = ["  " + " ".join(str(i + 1) for i in range(size))]
  lines.extend(f"{i + 1} " + " ".join(row) for i, row in enumerate(square))
  return "\n".join(lines)


def encrypt_with_custom_output(text: str, key: str = "", size: int = 5) -> str:
  """Encrypt using letter coordinates (A-E) instead of digits."""
  row_labels = "ABCDE"[:size]
  col_labels = "ABCDE"[:size]
  return encrypt(text, key, size, row_labels, col_labels)


def decrypt_with_custom_input(encrypted_text: str, key: str = "", size: int = 5) -> str:
  """Decrypt using letter coordinates (A-E) instead of digits."""
  row_labels = "ABCDE"[:size]
  col_labels = "ABCDE"[:size]
  return decrypt(encrypted_text, key, size, row_labels, col_labels)


if __name__ == "__main__":
  print("5x5 Polybius square:")
  print(print_square())
  print()

  source_text = "HELLO"
  print(f"Plaintext: {source_text}")

  encrypted = encrypt(source_text)
  print(f"Encrypted: {encrypted}")

  decrypted = decrypt(encrypted)
  print(f"Decrypted: {decrypted}")

  print("\nUsing key 'KEYWORD':")
  print(print_square("KEYWORD"))

  encrypted_key = encrypt(source_text, "KEYWORD")
  print(f"Encrypted: {encrypted_key}")

  decrypted_key = decrypt(encrypted_key, "KEYWORD")
  print(f"Decrypted: {decrypted_key}")

  print("\n6x6 Polybius square:")
  print(print_square(size=6))
