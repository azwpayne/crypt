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

  def test_trailing_whitespace_encoded(self):
    data = b"Hello \t"
    encoded = encode_qp(data)
    assert "=20" in encoded or "=09" in encoded.upper()
    assert decode_qp(encoded) == data

  def test_trailing_whitespace_before_newline(self):
    """Test trailing whitespace before newline is encoded."""
    data = b"Hello \t\nline2"
    encoded = encode_qp(data)
    assert "=20" in encoded or "=09" in encoded.upper()
    assert decode_qp(encoded) == data

  def test_crlf_handling(self):
    """Test CRLF sequence handling normalizes to LF on decode."""
    data = b"line1\r\nline2"
    encoded = encode_qp(data)
    # CRLF is normalized to LF during encode/decode roundtrip
    assert decode_qp(encoded) == b"line1\nline2"

  def test_decode_invalid_hex(self):
    """Test decoding invalid hex after = sign."""
    encoded = "Hello=GH"
    result = decode_qp(encoded)
    assert result == b"Hello=GH"

  def test_decode_multiline_no_softbreak(self):
    """Test decoding multiline without soft breaks."""
    encoded = "line1\nline2\nline3"
    result = decode_qp(encoded)
    assert result == b"line1\nline2\nline3"
