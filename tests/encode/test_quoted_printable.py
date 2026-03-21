"""Tests for Quoted-Printable encoding."""

from crypt.encode.quoted_printable import decode_qp, encode_qp


class TestQuotedPrintable:
  def test_plain_ascii_unchanged(self):
    text = b"Hello World"
    encoded = encode_qp(text)
    assert decode_qp(encoded) == text

  def test_non_ascii_encoded(self):
    data = b"\xff"
    encoded = encode_qp(data)
    assert "=FF" in encoded.upper()

  def test_roundtrip_binary(self):
    data = bytes(range(0, 256, 3))
    assert decode_qp(encode_qp(data)) == data

  def test_newline_preserved(self):
    data = b"line1\nline2"
    result = decode_qp(encode_qp(data))
    assert result == data

  def test_long_line_wraps(self):
    data = b"A" * 200
    encoded = encode_qp(data)
    for line in encoded.splitlines():
      assert len(line) <= 76
