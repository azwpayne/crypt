"""Quoted-Printable (QP) encoding — pure Python implementation.

RFC 2045 §6.7 compliant:
- Bytes outside printable ASCII (33-126, excluding '=') are encoded as =XX.
- Lines are wrapped at 76 characters using soft line breaks (=\r\n).
- Tab (\t) and space (0x20) are passed through (unless at end of line).
"""

_SAFE = frozenset(range(33, 127)) - {ord("=")}


def encode_qp(data: bytes, line_length: int = 76) -> str:
  """Encode *data* to a Quoted-Printable string."""
  lines: list[str] = []
  line: list[str] = []
  col = 0

  def _flush_line(soft: bool = True) -> None:
    nonlocal col
    if soft:
      lines.append("".join(line) + "=")
    else:
      lines.append("".join(line))
    line.clear()
    col = 0

  i = 0
  while i < len(data):
    byte = data[i]

    # Newline: hard line break
    if byte == ord("\n"):
      # Strip trailing space/tab before newline
      while line and line[-1] in (" ", "\t"):
        enc = f"={line.pop():02X}" if line[-1:] == [" "] else f"={ord(line.pop()):02X}"
        line.append(enc)
      lines.append("".join(line))
      line.clear()
      col = 0
      i += 1
      continue

    if byte == ord("\r") and i + 1 < len(data) and data[i + 1] == ord("\n"):
      while line and line[-1] in (" ", "\t"):
        popped = line.pop()
        line.append(f"={ord(popped):02X}")
      lines.append("".join(line))
      line.clear()
      col = 0
      i += 2
      continue

    # Encode token
    if byte in _SAFE or byte in (0x09, 0x20):  # safe printable, tab, space
      token = chr(byte)
    else:
      token = f"={byte:02X}"

    token_len = len(token)
    # Need room: token + possible soft-break "="
    if col + token_len >= line_length:
      _flush_line(soft=True)
    line.append(token)
    col += token_len
    i += 1

  # Final line — strip trailing whitespace
  while line and line[-1] in (" ", "\t"):
    popped = line.pop()
    enc = f"={ord(popped):02X}"
    col += len(enc) - 1
    if col > line_length:
      _flush_line(soft=True)
    line.append(enc)
  if line:
    lines.append("".join(line))

  return "\n".join(lines)


def decode_qp(encoded: str) -> bytes:
  """Decode a Quoted-Printable string back to bytes."""
  result = bytearray()
  lines = encoded.split("\n")
  for idx, line in enumerate(lines):
    # Soft line break: line ends with '='
    if line.endswith("="):
      line = line[:-1]  # strip soft break, no newline appended
    else:
      # Hard newline (re-add), but not after last segment
      add_nl = idx < len(lines) - 1

      i = 0
      while i < len(line):
        if line[i] == "=" and i + 2 < len(line):
          hex_str = line[i + 1 : i + 3]
          try:
            result.append(int(hex_str, 16))
            i += 3
          except ValueError:
            result.append(ord("="))
            i += 1
        else:
          result.append(ord(line[i]))
          i += 1
      if add_nl:
        result.append(ord("\n"))
      continue

    # Process soft-break line (no newline)
    i = 0
    while i < len(line):
      if line[i] == "=" and i + 2 < len(line):
        hex_str = line[i + 1 : i + 3]
        try:
          result.append(int(hex_str, 16))
          i += 3
        except ValueError:
          result.append(ord("="))
          i += 1
      else:
        result.append(ord(line[i]))
        i += 1

  return bytes(result)
