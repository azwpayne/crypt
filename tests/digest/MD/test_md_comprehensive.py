"""Comprehensive tests for all MD hash algorithms.

Tests for MD2, MD4, MD5, and MD6.
"""

from __future__ import annotations

import hashlib
from crypt.digest.MD.md2 import md2
from crypt.digest.MD.md4 import md4
from crypt.digest.MD.md5 import (
  FF,
  GG,
  HH,
  II,
  MD5State,
  bitwise_choice,
  bitwise_majority,
  bitwise_nor_mix,
  bitwise_xor3,
  ff,
  gg,
  hh,
  ii,
  left_rotate,
  md5,
  pad_message,
)
from crypt.digest.MD.md6 import md6, md6_128, md6_256, md6_512

import pytest
from Crypto.Hash import MD2, MD4, MD5

from tests import BYTE_TEST_CASES


class TestMD2:
  """Comprehensive tests for MD2 implementation."""

  @pytest.mark.parametrize(
    ("msg", "expected"),
    [
      # RFC 1319 test vectors
      (b"", "8350e5a3e24c153df2275c9f80692773"),
      (b"a", "32ec01ec4a6dac72c0ab96fb34c0b5d1"),
      (b"abc", "da853b0d3f88d99b30283a69e6ded6bb"),
      (b"message digest", "ab4f496bfb2a530b219ff33031fe06b0"),
      (b"abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b"),
      (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "da33def2a42df13975352846c30338cd",
      ),
      (
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "d5976f79d83d3a0dc9806c3c66f3efd8",
      ),
    ],
  )
  def test_rfc_vectors(self, msg, expected):
    """Test MD2 against RFC 1319 test vectors."""
    result = md2(msg)
    assert result == expected

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_vs_pycryptodome(self, msg):
    """Test MD2 against PyCryptodome reference."""
    result = md2(msg)
    expected = MD2.new(msg).hexdigest()  # noqa: S303
    assert result == expected

  def test_output_length(self):
    """Test MD2 produces correct output length."""
    result = md2(b"test")
    assert len(result) == 32  # 128 bits = 32 hex chars

  def test_string_input(self):
    """Test MD2 with string input."""
    result = md2("hello")
    expected = md2(b"hello")
    assert result == expected


class TestMD4:
  """Comprehensive tests for MD4 implementation."""

  @pytest.mark.parametrize(
    ("msg", "expected"),
    [
      # RFC 1320 test vectors
      (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
      (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
      (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
      (b"message digest", "d9130a8164549fe818874806e1c7014b"),
      (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
      (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "043f8582f241db351ce627e153e7f0e4",
      ),
      (
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "e33b4ddc9c38f2199c3e7b164fcc0536",
      ),
    ],
  )
  def test_rfc_vectors(self, msg, expected):
    """Test MD4 against RFC 1320 test vectors."""
    result = md4(msg)
    assert result == expected

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_vs_pycryptodome(self, msg):
    """Test MD4 against PyCryptodome reference."""
    result = md4(msg)
    expected = MD4.new(msg).hexdigest()  # noqa: S303
    assert result == expected

  def test_output_length(self):
    """Test MD4 produces correct output length."""
    result = md4(b"test")
    assert len(result) == 32  # 128 bits = 32 hex chars

  def test_string_input(self):
    """Test MD4 with string input."""
    result = md4("hello")
    expected = md4(b"hello")
    assert result == expected


class TestMD5:
  """Comprehensive tests for MD5 implementation."""

  @pytest.mark.parametrize(
    ("msg", "expected"),
    [
      # RFC 1321 test vectors
      (b"", "d41d8cd98f00b204e9800998ecf8427e"),
      (b"a", "0cc175b9c0f1b6a831c399e269772661"),
      (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
      (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
      (b"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
      (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "d174ab98d277d9f5a5611c2c9f419d9f",
      ),
      (
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "57edf4a22be3c955ac49da2e2107b67a",
      ),
    ],
  )
  def test_rfc_vectors(self, msg, expected):
    """Test MD5 against RFC 1321 test vectors."""
    result = md5(msg)
    assert result == expected

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_vs_hashlib(self, msg):
    """Test MD5 against hashlib reference."""
    result = md5(msg)
    expected = hashlib.md5(msg).hexdigest()
    assert result == expected

  @pytest.mark.parametrize(
    "msg",
    BYTE_TEST_CASES,
  )
  def test_vs_pycryptodome(self, msg):
    """Test MD5 against PyCryptodome reference."""
    result = md5(msg)
    expected = MD5.new(msg).hexdigest()  # noqa: S303
    assert result == expected

  def test_output_length(self):
    """Test MD5 produces correct output length."""
    result = md5(b"test")
    assert len(result) == 32  # 128 bits = 32 hex chars

  def test_string_input(self):
    """Test MD5 with string input."""
    result = md5("hello")
    expected = md5(b"hello")
    assert result == expected


class TestMD5Internal:
  """Tests for MD5 internal functions."""

  def test_left_rotate(self):
    """Test left rotation function."""
    assert left_rotate(0x80000000, 1) == 0x00000001
    assert left_rotate(0x00000001, 1) == 0x00000002
    assert left_rotate(0xFFFFFFFF, 1) == 0xFFFFFFFF
    assert left_rotate(0x12345678, 4) == 0x23456781

  def test_bitwise_choice(self):
    """Test bitwise choice function."""
    # If all mask bits are 1, should return if_true
    assert bitwise_choice(0xFFFFFFFF, 0x12345678, 0x87654321) == 0x12345678
    # If all mask bits are 0, should return if_false
    assert bitwise_choice(0x00000000, 0x12345678, 0x87654321) == 0x87654321

  def test_bitwise_majority(self):
    """Test bitwise majority function."""
    # All same -> return that value
    assert bitwise_majority(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) == 0xFFFFFFFF
    assert bitwise_majority(0x00000000, 0x00000000, 0x00000000) == 0x00000000

  def test_bitwise_xor3(self):
    """Test triple XOR function."""
    assert bitwise_xor3(0x00000000, 0x00000000, 0x00000000) == 0x00000000
    assert bitwise_xor3(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) == 0xFFFFFFFF
    assert bitwise_xor3(0x12345678, 0x87654321, 0x00000000) == 0x95511559

  def test_bitwise_nor_mix(self):
    """Test NOR mix function."""
    result = bitwise_nor_mix(0x12345678, 0x87654321, 0x00000000)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF

  def test_md5_state_copy(self):
    """Test MD5State copy method."""
    state = MD5State(a=1, b=2, c=3, d=4)
    copy = state.copy()
    assert copy.a == state.a
    assert copy.b == state.b
    assert copy.c == state.c
    assert copy.d == state.d
    # Modify original, copy should not change
    state.a = 100
    assert copy.a == 1

  def test_md5_state_add(self):
    """Test MD5State add method."""
    state1 = MD5State(a=1, b=2, c=3, d=4)
    state2 = MD5State(a=5, b=6, c=7, d=8)
    state1.add(state2)
    assert state1.a == 6
    assert state1.b == 8
    assert state1.c == 10
    assert state1.d == 12

  def test_md5_state_to_bytes(self):
    """Test MD5State to_bytes method."""
    state = MD5State(a=0x67452301, b=0xEFCDAB89, c=0x98BADCFE, d=0x10325476)
    result = state.to_bytes()
    assert isinstance(result, bytes)
    assert len(result) == 16

  def test_pad_message(self):
    """Test message padding."""
    # Empty message should be padded to 64 bytes
    padded = pad_message(b"")
    assert len(padded) == 64
    assert padded[0] == 0x80

    # Message of 55 bytes should be padded to 64 bytes
    padded = pad_message(b"a" * 55)
    assert len(padded) == 64

    # Message of 56 bytes should be padded to 128 bytes
    padded = pad_message(b"a" * 56)
    assert len(padded) == 128

  def test_round_functions(self):
    """Test round functions FF, GG, HH, II."""
    # Test with known values
    a, b, c, d, x = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0

    result_ff = ff(a, b, c, d, x, s=7, ac=0xD76AA478)
    assert isinstance(result_ff, int)
    assert 0 <= result_ff <= 0xFFFFFFFF

    result_gg = gg(a, b, c, d, x, s=5, ac=0xF61E2562)
    assert isinstance(result_gg, int)
    assert 0 <= result_gg <= 0xFFFFFFFF

    result_hh = hh(a, b, c, d, x, s=4, ac=0xFFFA3942)
    assert isinstance(result_hh, int)
    assert 0 <= result_hh <= 0xFFFFFFFF

    result_ii = ii(a, b, c, d, x, s=6, ac=0xF4292244)
    assert isinstance(result_ii, int)
    assert 0 <= result_ii <= 0xFFFFFFFF

  def test_uppercase_aliases(self):
    """Test uppercase function aliases."""
    a, b, c, d, x = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0
    assert FF(a, b, c, d, x, s=7, ac=0xD76AA478) == ff(
      a, b, c, d, x, s=7, ac=0xD76AA478
    )
    assert GG(a, b, c, d, x, s=5, ac=0xF61E2562) == gg(
      a, b, c, d, x, s=5, ac=0xF61E2562
    )
    assert HH(a, b, c, d, x, s=4, ac=0xFFFA3942) == hh(
      a, b, c, d, x, s=4, ac=0xFFFA3942
    )
    assert II(a, b, c, d, x, s=6, ac=0xF4292244) == ii(
      a, b, c, d, x, s=6, ac=0xF4292244
    )


class TestMD6:
  """Comprehensive tests for MD6 implementation."""

  def test_md6_basic(self):
    """Test basic MD6 calculation."""
    result = md6(b"hello")
    assert isinstance(result, str)
    assert len(result) == 64  # 256 bits = 64 hex chars

  def test_md6_128(self):
    """Test MD6-128 variant."""
    result = md6_128(b"test")
    assert len(result) == 32  # 128 bits = 32 hex chars

  def test_md6_256(self):
    """Test MD6-256 variant."""
    result = md6_256(b"test")
    assert len(result) == 64  # 256 bits = 64 hex chars

  def test_md6_512(self):
    """Test MD6-512 variant."""
    result = md6_512(b"test")
    assert len(result) == 128  # 512 bits = 128 hex chars

  def test_md6_empty(self):
    """Test MD6 with empty input."""
    result = md6(b"")
    assert isinstance(result, str)
    assert len(result) == 64

  def test_md6_string_input(self):
    """Test MD6 with string input."""
    result1 = md6("hello")
    result2 = md6(b"hello")
    assert result1 == result2

  def test_md6_deterministic(self):
    """Test MD6 is deterministic."""
    data = b"test data"
    results = [md6(data) for _ in range(10)]
    assert all(r == results[0] for r in results)

  def test_md6_large_input(self):
    """Test MD6 with large input."""
    data = b"x" * 10000
    result = md6(data)
    assert isinstance(result, str)
    assert len(result) == 64

  def test_md6_different_sizes(self):
    """Test that different hash sizes produce different outputs."""
    data = b"test"
    r128 = md6(data, 128)
    r256 = md6(data, 256)
    r512 = md6(data, 512)
    # Different sizes should have different lengths
    assert len(r128) == 32
    assert len(r256) == 64
    assert len(r512) == 128


class TestMDEdgeCases:
  """Edge case tests for all MD implementations."""

  def test_large_input(self):
    """Test with large input data."""
    large_data = b"x" * 100000
    assert len(md2(large_data)) == 32
    assert len(md4(large_data)) == 32
    assert len(md5(large_data)) == 32
    assert len(md6(large_data)) == 64

  def test_binary_data(self):
    """Test with binary data containing all byte values."""
    data = bytes(range(256))
    assert len(md2(data)) == 32
    assert len(md4(data)) == 32
    assert len(md5(data)) == 32
    assert len(md6(data)) == 64

  def test_unicode_data(self):
    """Test with UTF-8 encoded Unicode data."""
    data = "Hello, 世界! 🌍".encode()
    assert len(md2(data)) == 32
    assert len(md4(data)) == 32
    assert len(md5(data)) == 32
    assert len(md6(data)) == 64

  def test_deterministic(self):
    """Test all MD algorithms are deterministic."""
    data = b"deterministic test"
    for func in [md2, md4, md5, md6]:
      results = [func(data) for _ in range(10)]
      assert all(r == results[0] for r in results)

  def test_different_inputs(self):
    """Test that different inputs produce different outputs."""
    data1 = b"data1"
    data2 = b"data2"
    for func in [md2, md4, md5, md6]:
      assert func(data1) != func(data2)
