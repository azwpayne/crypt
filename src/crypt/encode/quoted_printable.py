"""Quoted-Printable (QP) encoding — pure Python implementation.

RFC 2045 §6.7 compliant:
- Bytes outside printable ASCII (33-126, excluding '=') are encoded as =XX.
- Lines are wrapped at 76 characters using soft line breaks (=\r\n).
- Tab (\t) and space (0x20) are passed through (unless at end of line).
"""

_SAFE = frozenset(range(33, 127)) - {ord("=")}


def _encode_trailing_ws(line: list[str]) -> None:
  """Encode trailing space/tab in *line* in-place."""
  while line and line[-1] in (" ", "\t"):
    popped = line.pop()
    line.append(f"={ord(popped):02X}")


def _decode_segment(content: str, result: bytearray) -> None:
  """Decode one QP line segment into *result*."""
  i = 0
  while i < len(content):
    if content[i] == "=" and i + 2 < len(content):
      hex_str = content[i + 1 : i + 3]
      try:
        result.append(int(hex_str, 16))
        i += 3
      except ValueError:
        result.append(ord("="))
        i += 1
    else:
      result.append(ord(content[i]))
      i += 1


def encode_qp(data: bytes, line_length: int = 76) -> str:
  """Encode *data* to a Quoted-Printable string."""
  lines: list[str] = []
  line: list[str] = []
  col = 0

  def _flush(*, soft: bool = True) -> None:
    nonlocal col
    lines.append("".join(line) + ("=" if soft else ""))
    line.clear()
    col = 0

  i = 0
  while i < len(data):
    byte = data[i]

    if byte in (ord("\n"), ord("\r")):
      _encode_trailing_ws(line)
      if byte == ord("\r") and i + 1 < len(data) and data[i + 1] == ord("\n"):
        i += 1
      _flush(soft=False)
      i += 1
      continue

    tok = chr(byte) if byte in _SAFE else f"={byte:02X}"
    if col + len(tok) > line_length - 1:
      _flush()
    line.append(tok)
    col += len(tok)
    i += 1

  _encode_trailing_ws(line)
  lines.append("".join(line))
  return "\n".join(lines)


def decode_qp(encoded: str) -> bytes:
  """Decode a Quoted-Printable string back to bytes."""
  result = bytearray()
  lines = encoded.split("\n")
  for idx, line in enumerate(lines):
    if line.endswith("="):
      _decode_segment(line[:-1], result)
    else:
      _decode_segment(line, result)
      if idx < len(lines) - 1:
        result.append(ord("\n"))
  return bytes(result)
