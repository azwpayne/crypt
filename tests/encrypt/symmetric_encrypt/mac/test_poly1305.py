# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_poly1305.py
# @time    : 2026/03/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Unit tests for Poly1305 implementation

from crypt.digest.poly1305 import (
  poly1305_mac,
  poly1305_verify,
)

import pytest


class TestPoly1305:
  """Test cases for Poly1305 MAC."""

  def test_basic_mac(self):
    """Test basic Poly1305 MAC computation."""
    key = b"\x00" * 32  # 32-byte key
    message = b"Hello, World!"
    result = poly1305_mac(key, message)
    assert len(result) == 16
    assert isinstance(result, bytes)

  def test_deterministic(self):
    """Test that MAC is deterministic for same inputs."""
    key = b"\x01" * 32
    message = b"test message"
    result1 = poly1305_mac(key, message)
    result2 = poly1305_mac(key, message)
    assert result1 == result2

  def test_different_keys(self):
    """Test that different keys produce different MACs."""
    key1 = b"\x00" * 32
    key2 = b"\x01" * 32
    message = b"test message"
    result1 = poly1305_mac(key1, message)
    result2 = poly1305_mac(key2, message)
    assert result1 != result2

  def test_different_messages(self):
    """Test that different messages produce different MACs."""
    key = b"\x01" * 16 + b"\x02" * 16  # Non-zero key
    message1 = b"message 1"
    message2 = b"message 2"
    result1 = poly1305_mac(key, message1)
    result2 = poly1305_mac(key, message2)
    assert result1 != result2

  def test_empty_message(self):
    """Test MAC of empty message."""
    key = b"\x00" * 32
    message = b""
    result = poly1305_mac(key, message)
    assert len(result) == 16

  def test_long_message(self):
    """Test MAC of long message."""
    key = b"\x00" * 32
    message = b"A" * 1000
    result = poly1305_mac(key, message)
    assert len(result) == 16

  def test_key_too_short(self):
    """Test that short key raises ValueError."""
    key = b"\x00" * 16
    message = b"test"
    with pytest.raises(ValueError, match="32 bytes"):
      poly1305_mac(key, message)

  def test_key_too_long(self):
    """Test that long key raises ValueError."""
    key = b"\x00" * 64
    message = b"test"
    with pytest.raises(ValueError, match="32 bytes"):
      poly1305_mac(key, message)

  def test_string_inputs(self):
    """Test that string inputs work."""
    key = "a" * 32
    message = "test message"
    result = poly1305_mac(key, message)
    assert len(result) == 16

  def test_verify_correct(self):
    """Test verification of correct MAC."""
    key = b"\x00" * 32
    message = b"test message"
    tag = poly1305_mac(key, message)
    assert poly1305_verify(key, message, tag) is True

  def test_verify_incorrect(self):
    """Test verification of incorrect MAC."""
    key = b"\x00" * 32
    message = b"test message"
    tag = poly1305_mac(key, message)
    # Modify the tag
    wrong_tag = bytes([tag[0] ^ 1]) + tag[1:]
    assert poly1305_verify(key, message, wrong_tag) is False

  def test_verify_wrong_message(self):
    """Test verification with wrong message."""
    key = b"\x01" * 16 + b"\x02" * 16  # Non-zero key
    message = b"test message"
    tag = poly1305_mac(key, message)
    assert poly1305_verify(key, b"wrong message", tag) is False

  def test_verify_wrong_key(self):
    """Test verification with wrong key."""
    key = b"\x00" * 32
    message = b"test message"
    tag = poly1305_mac(key, message)
    wrong_key = b"\x01" * 32
    assert poly1305_verify(wrong_key, message, tag) is False

  def test_verify_wrong_tag_length(self):
    """Test verification with wrong tag length."""
    key = b"\x00" * 32
    message = b"test message"
    wrong_tag = b"\x00" * 15  # Should be 16 bytes
    assert poly1305_verify(key, message, wrong_tag) is False


if __name__ == "__main__":
  pytest.main([__file__, "-v"])
