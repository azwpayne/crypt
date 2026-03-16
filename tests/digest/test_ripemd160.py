# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_ripemd160.py
# @time    : 2026/3/15
# @desc    : Tests for RIPEMD-160 hash algorithm

from __future__ import annotations

from crypt.digest.ripemd160 import ripemd160

import pytest
from tests import BYTE_TEST_CASES


class TestRipemd160:
  """Test RIPEMD-160 implementation against known test vectors."""

  # RIPEMD-160 test vectors from the original paper
  TEST_VECTORS: list[tuple[bytes | str, str]] = [  # noqa: RUF012
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (
      b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    ),
    (
      b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "b0e20b6e3116640286ed3a87a5713079b21f5189",
    ),
    (
      b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
    ),
  ]

  @pytest.mark.parametrize(("msg", "expected"), TEST_VECTORS)
  def test_ripemd160_vectors(self, msg: bytes | str, expected: str):
    """Verify RIPEMD-160 against known test vectors."""
    result = ripemd160(msg)
    assert result == expected, f"RIPEMD-160 mismatch for: {msg!r}"

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_ripemd160_consistency(self, msg):
    """Verify RIPEMD-160 produces consistent results."""
    result1 = ripemd160(msg)
    result2 = ripemd160(msg)
    assert result1 == result2
    assert len(result1) == 40  # 160 bits = 40 hex chars

  def test_ripemd160_empty(self):
    """Test RIPEMD-160 with empty input."""
    result = ripemd160(b"")
    expected = "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert result == expected

  def test_ripemd160_abc(self):
    """Test RIPEMD-160 with 'abc'."""
    result = ripemd160(b"abc")
    expected = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert result == expected

  def test_ripemd160_string_input(self):
    """Test RIPEMD-160 with string input."""
    result = ripemd160("hello")
    expected = ripemd160(b"hello")
    assert result == expected

  def test_ripemd160_bytes_input(self):
    """Test RIPEMD-160 with bytes input."""
    result = ripemd160(b"hello")
    expected = "108f07b8382412612c048d07d13f814118445acd"
    assert result == expected

  def test_ripemd160_large_input(self):
    """Test RIPEMD-160 with large input."""
    data = b"a" * 10000
    result = ripemd160(data)
    assert len(result) == 40
    # Verify consistency
    assert ripemd160(data) == result

  def test_ripemd160_binary_data(self):
    """Test RIPEMD-160 with binary data."""
    data = bytes(range(256))
    result = ripemd160(data)
    assert len(result) == 40
    # Verify consistency
    assert ripemd160(data) == result

  def test_ripemd160_multiblock(self):
    """Test RIPEMD-160 with multi-block message (>64 bytes)."""
    # 64 bytes is one block, test with more
    data = b"x" * 128
    result = ripemd160(data)
    assert len(result) == 40

  def test_ripemd160_unicode(self):
    """Test RIPEMD-160 with unicode string."""
    result = ripemd160("hello world")
    expected = ripemd160(b"hello world")
    assert result == expected


class TestRipemd160Helpers:
  """Test RIPEMD-160 helper functions."""

  def test_left_rotate(self):
    """Test left rotate function."""
    from crypt.digest.ripemd160 import _left_rotate

    # Test basic rotation
    result = _left_rotate(0b10110000, 2)
    expected = ((0b10110000 << 2) | (0b10110000 >> (32 - 2))) & 0xFFFFFFFF
    assert result == expected

    # Test rotation wraps around
    result = _left_rotate(0x80000000, 1)
    expected = 0x1  # MSB becomes LSB
    assert result == expected

  def test_nonlinear_functions(self):
    """Test nonlinear functions."""
    from crypt.digest.ripemd160 import _f1, _f2, _f3, _f4, _f5

    x, y, z = 0x12345678, 0x87654321, 0xABCDEF00

    # f1: x ^ y ^ z
    assert _f1(x, y, z) == (x ^ y ^ z) & 0xFFFFFFFF

    # f2: (x & y) | (~x & z)
    assert _f2(x, y, z) == ((x & y) | (~x & z)) & 0xFFFFFFFF

    # f3: (x | ~y) ^ z
    assert _f3(x, y, z) == ((x | ~y) ^ z) & 0xFFFFFFFF

    # f4: (x & z) | (y & ~z)
    assert _f4(x, y, z) == ((x & z) | (y & ~z)) & 0xFFFFFFFF

    # f5: x ^ (y | ~z)
    assert _f5(x, y, z) == (x ^ (y | ~z)) & 0xFFFFFFFF
