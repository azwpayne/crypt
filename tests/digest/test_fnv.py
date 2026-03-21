"""Tests for FNV hash functions."""

from crypt.digest.fnv import fnv1_32, fnv1_64, fnv1_128, fnv1a_32, fnv1a_64, fnv1a_128


class TestFNV32:
  def test_fnv1_32_empty(self):
    # FNV-1 32-bit of empty string is the offset basis
    assert fnv1_32(b"") == 0x811C9DC5

  def test_fnv1a_32_empty(self):
    assert fnv1a_32(b"") == 0x811C9DC5

  def test_fnv1a_32_hello(self):
    # Known vector
    assert fnv1a_32(b"hello") == 0x4F9F2CAB

  def test_fnv1_32_differs_from_fnv1a(self):
    data = b"test data"
    assert fnv1_32(data) != fnv1a_32(data)

  def test_fnv1a_32_consistency(self):
    assert fnv1a_32(b"abc") == fnv1a_32(b"abc")


class TestFNV64:
  def test_fnv1_64_empty(self):
    assert fnv1_64(b"") == 0xCBF29CE484222325

  def test_fnv1a_64_empty(self):
    assert fnv1a_64(b"") == 0xCBF29CE484222325

  def test_fnv1a_64_hello(self):
    assert fnv1a_64(b"hello") == 0xA430D84680AABD0B

  def test_64bit_range(self):
    result = fnv1a_64(b"arbitrary data")
    assert 0 <= result < 2**64


class TestFNV128:
  def test_fnv1_128_empty(self):
    assert fnv1_128(b"") == 0x6C62272E07BB0142628B408779AEF38F

  def test_fnv1a_128_consistency(self):
    assert fnv1a_128(b"test") == fnv1a_128(b"test")

  def test_128bit_range(self):
    result = fnv1a_128(b"data")
    assert 0 <= result < 2**128
