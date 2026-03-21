"""Tests for Adler-32 checksum."""

from crypt.digest.adler32 import adler32, adler32_hex


class TestAdler32:
  def test_empty(self):
    assert adler32(b"") == 1  # initial value

  def test_known_wikipedia(self):
    # Wikipedia example: "Wikipedia" -> 0x11E60398
    assert adler32(b"Wikipedia") == 0x11E60398

  def test_hex_length(self):
    assert len(adler32_hex(b"test")) == 8

  def test_single_byte(self):
    # 'A' = 65; a=1+65=66, b starts at 0 so b=0+66=66 -> (66<<16)|66
    result = adler32(b"A")
    assert result == (66 << 16) | 66

  def test_incremental(self):
    v = adler32(b"Hello")
    v = adler32(b", World!", v)
    assert v == adler32(b"Hello, World!")
