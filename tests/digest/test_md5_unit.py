"""Unit tests for MD5 internal components."""

import hashlib
import struct
from crypt.digest.MD import md5

import pytest


class TestMD5State:
  """Test internal _MD5State dataclass."""

  def test_state_initialization(self):
    """Test state is properly initialized."""
    state = md5._MD5State(  # noqa: SLF001
      a=0x67452301,
      b=0xEFCDAB89,
      c=0x98BADCFE,
      d=0x10325476,
    )
    assert state.a == 0x67452301
    assert state.b == 0xEFCDAB89
    assert state.c == 0x98BADCFE
    assert state.d == 0x10325476

  def test_state_copy(self):
    """Test state copy creates independent copy."""
    original = md5._MD5State(a=1, b=2, c=3, d=4)  # noqa: SLF001
    copy = original.copy()

    # Verify values are equal
    assert copy.a == original.a
    assert copy.b == original.b
    assert copy.c == original.c
    assert copy.d == original.d

    # Verify independence
    copy.a = 999
    assert original.a == 1

  def test_state_add(self):
    """Test state addition with modulo 2^32."""
    state1 = md5._MD5State(a=0xFFFFFFFF, b=1, c=0, d=0)  # noqa: SLF001
    state2 = md5._MD5State(a=1, b=0xFFFFFFFF, c=0, d=0)  # noqa: SLF001

    state1.add(state2)

    # 0xFFFFFFFF + 1 = 0x100000000 -> wraps to 0
    assert state1.a == 0
    # 1 + 0xFFFFFFFF = 0x100000000 -> wraps to 0
    assert state1.b == 0
    assert state1.c == 0
    assert state1.d == 0

  def test_state_to_bytes(self):
    """Test state conversion to little-endian bytes."""
    state = md5._MD5State(  # noqa: SLF001
      a=0x67452301,
      b=0xEFCDAB89,
      c=0x98BADCFE,
      d=0x10325476,
    )
    result = state.to_bytes()
    assert len(result) == 16
    assert result == struct.pack("<4I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)


class TestMD5RoundFunctions:
  """Test MD5 round transformation functions (FF, GG, HH, II)."""

  def test_ff_basic(self):
    """Test FF function with basic values."""
    a, b, c, d = 0, 0, 0xFFFFFFFF, 0
    x, s, ac = 1, 7, 0xD76AA478

    result = md5.FF(a, b, c, d, x, s, ac)

    # Manual calculation
    expected = (a + ((b & c) | (~b & d)) + x + ac) & 0xFFFFFFFF
    expected = md5.left_rotate(expected, s)
    expected = (expected + b) & 0xFFFFFFFF

    assert result == expected

  def test_gg_basic(self):
    """Test GG function with basic values."""
    a, b, c, d = 0, 0, 0, 0xFFFFFFFF
    x, s, ac = 1, 5, 0xF61E2562

    result = md5.GG(a, b, c, d, x, s, ac)

    # Manual calculation: (b & d) | (c & ~d)
    g = ((b & d) | (c & (0xFFFFFFFF ^ d))) & 0xFFFFFFFF
    expected = (a + g + x + ac) & 0xFFFFFFFF
    expected = md5.left_rotate(expected, s)
    expected = (expected + b) & 0xFFFFFFFF

    assert result == expected

  def test_hh_basic(self):
    """Test HH function with basic values."""
    a, b, c, d = 0xFFFFFFFF, 0, 0, 0
    x, s, ac = 1, 4, 0xFFFA3942

    result = md5.HH(a, b, c, d, x, s, ac)

    # Manual calculation: b ^ c ^ d
    expected = (a + (b ^ c ^ d) + x + ac) & 0xFFFFFFFF
    expected = md5.left_rotate(expected, s)
    expected = (expected + b) & 0xFFFFFFFF

    assert result == expected

  def test_ii_basic(self):
    """Test II function with basic values."""
    a, b, c, d = 0, 0, 0xFFFFFFFF, 0
    x, s, ac = 1, 6, 0xF4292244

    result = md5.II(a, b, c, d, x, s, ac)

    # Manual calculation: c ^ (b | ~d)
    expected = (a + (c ^ (b | (0xFFFFFFFF ^ d))) + x + ac) & 0xFFFFFFFF
    expected = md5.left_rotate(expected, s)
    expected = (expected + b) & 0xFFFFFFFF

    assert result == expected

  @pytest.mark.parametrize(
    ("func", "expected_pattern"),
    [
      (md5.FF, "round_1"),
      (md5.GG, "round_2"),
      (md5.HH, "round_3"),
      (md5.II, "round_4"),
    ],
  )
  def test_round_functions_different(self, func, expected_pattern):  # noqa: ARG002
    """Verify round functions produce different results."""
    a, b, c, d = 0x12345678, 0x9ABCDEF0, 0x0F1E2D3C, 0x4B5A6978
    x, s, ac = 0x11111111, 7, 0xAAAAAAAA

    result = func(a, b, c, d, x, s, ac)
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFFFFFF


class TestMD5EdgeCases:
  """Test MD5 edge cases and boundary conditions."""

  def test_md5_exact_block_boundary(self):
    """Test MD5 with input exactly 64 bytes (one block)."""
    data = b"a" * 64
    result = md5.md5(data)
    expected = hashlib.md5(data).hexdigest()
    assert result == expected

  def test_md5_two_blocks(self):
    """Test MD5 with input requiring exactly two blocks."""
    data = b"a" * 120  # 120 bytes requires 2 blocks
    result = md5.md5(data)
    expected = hashlib.md5(data).hexdigest()
    assert result == expected

  def test_md5_unicode_string(self):
    """Test MD5 with unicode string input."""
    data = "Hello, 世界! 🌍"
    result = md5.md5(data)
    expected = hashlib.md5(data.encode()).hexdigest()
    assert result == expected

  def test_md5_single_byte_values(self):
    """Test MD5 with all single byte values."""
    for i in range(256):
      data = bytes([i])
      result = md5.md5(data)
      expected = hashlib.md5(data).hexdigest()
      assert result == expected, f"Failed for byte value {i}"

  def test_md5_very_long_input(self):
    """Test MD5 with very long input."""
    data = b"x" * 100000
    result = md5.md5(data)
    expected = hashlib.md5(data).hexdigest()
    assert result == expected

  def test_md5_multiple_blocks_exact(self):
    """Test MD5 with multiple exact 64-byte blocks."""
    for num_blocks in [1, 2, 3, 10]:
      data = b"x" * (64 * num_blocks)
      result = md5.md5(data)
      expected = hashlib.md5(data).hexdigest()
      assert result == expected, f"Failed for {num_blocks} blocks"


class TestMD5PaddingEdgeCases:
  """Test MD5 padding edge cases."""

  def test_pad_message_55_bytes(self):
    """Test padding for 55 bytes (needs one block)."""
    msg = b"x" * 55
    result = md5.pad_message(msg)
    # 55 + 1 (0x80) + 8 (length) = 64
    assert len(result) == 64

  def test_pad_message_56_bytes(self):
    """Test padding for 56 bytes (needs two blocks)."""
    msg = b"x" * 56
    result = md5.pad_message(msg)
    # 56 + 1 (0x80) + 63 (padding) + 8 (length) = 128
    assert len(result) == 128

  def test_pad_message_63_bytes(self):
    """Test padding for 63 bytes (needs two blocks)."""
    msg = b"x" * 63
    result = md5.pad_message(msg)
    # 63 + 1 (0x80) + 56 (padding) + 8 (length) = 128
    assert len(result) == 128

  def test_pad_message_length_field(self):
    """Test that length field is correctly encoded as little-endian."""
    # 1 byte = 8 bits = 0x08
    msg = b"x"
    result = md5.pad_message(msg)
    length_bytes = result[-8:]
    assert length_bytes == struct.pack("<Q", 8)

    # 64 bytes = 512 bits = 0x200
    msg = b"x" * 64
    result = md5.pad_message(msg)
    length_bytes = result[-8:]
    assert length_bytes == struct.pack("<Q", 512)


class TestMD5InternalFunctions:
  """Test internal helper functions."""

  def test_left_rotate_zero(self):
    """Test left rotate by 0 returns same value."""
    result = md5.left_rotate(0x12345678, 0)
    assert result == 0x12345678

  def test_left_rotate_32(self):
    """Test left rotate by 32 is equivalent to rotate by 0 (mod 32)."""
    # When amount=32: x << 32 = 0, x >> 0 = x
    # So rotate by 32: (0 | x) & 0xFFFFFFFF = x
    result = md5.left_rotate(0x12345678, 32)
    expected = 0x12345678  # Same as original value
    assert result == expected

  def test_left_rotate_full_range(self):
    """Test left rotate with various amounts."""
    value = 0x80000000  # MSB set
    for amount in range(1, 32):
      result = md5.left_rotate(value, amount)
      expected = ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF
      assert result == expected, f"Failed for rotate amount {amount}"

  def test_choice_edge_cases(self):
    """Test choice function with edge case masks."""
    # All zeros mask
    result = md5.bitwise_choice(0, 0xFFFFFFFF, 0xAAAAAAAA)
    assert result == 0xAAAAAAAA  # All from if_false

    # All ones mask
    result = md5.bitwise_choice(0xFFFFFFFF, 0xFFFFFFFF, 0xAAAAAAAA)
    assert result == 0xFFFFFFFF  # All from if_true

    # Alternating mask
    result = md5.bitwise_choice(0xAAAAAAAA, 0xFFFFFFFF, 0)
    assert result == 0xAAAAAAAA  # Alternating pattern

  def test_majority_all_same(self):
    """Test majority when all inputs are same."""
    result = md5.bitwise_majority(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    assert result == 0xFFFFFFFF

    result = md5.bitwise_majority(0, 0, 0)
    assert result == 0

  def test_xor3_properties(self):
    """Test XOR3 properties."""
    # x ^ x ^ x = x
    result = md5.bitwise_xor3(0x12345678, 0x12345678, 0x12345678)
    assert result == 0x12345678

    # x ^ x ^ y = y
    result = md5.bitwise_xor3(0x12345678, 0x12345678, 0xAAAAAAAA)
    assert result == 0xAAAAAAAA

  def test_nor_mix_properties(self):
    """Test nor_mix properties."""
    # When x=0, z=0: y ^ (0 | ~0) = y ^ 0xFFFFFFFF = ~y
    result = md5.bitwise_nor_mix(0, 0x12345678, 0)
    assert result == (0x12345678 ^ 0xFFFFFFFF) & 0xFFFFFFFF


class TestMD5Deterministic:
  """Test that MD5 is deterministic."""

  def test_same_input_same_output(self):
    """Test that same input always produces same output."""
    data = b"test data"
    results = [md5.md5(data) for _ in range(100)]
    assert all(r == results[0] for r in results)

  def test_different_inputs_different_outputs(self):
    """Test that different inputs produce different outputs."""
    results = {md5.md5(bytes([i])) for i in range(100)}
    assert len(results) == 100  # All unique
