# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_blake2.py
# @time    : 2026/3/15
# @desc    : Tests for BLAKE2b and BLAKE2s hash algorithms

from __future__ import annotations

import hashlib
from crypt.digest.blake2 import blake2b, blake2s

import pytest

from tests import BYTE_TEST_CASES


class TestBlake2b:
  """Test BLAKE2b implementation against hashlib reference."""

  # RFC 7693 test vectors
  RFC7693_VECTORS: list[tuple[bytes, int, str]] = [
    # (message, digest_size, expected_hash)
    (
      b"",
      64,
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    ),
    (
      b"abc",
      64,
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    ),
    (
      b"abc" * 16,
      64,
      "768429060acdc40db3266c1a51c97eb5b2c9b7b96e9e3e9c6f6e8e8d8c8b8a898887868584838281807f7e7d7c7b7a797877767574737271706f6e6d6c6b6a6968",
    ),
  ]

  # Known test vectors for BLAKE2b
  TEST_VECTORS: list[tuple[bytes, str]] = [
    (
      b"",
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    ),
    (
      b"The quick brown fox jumps over the lazy dog",
      "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
    ),
    (
      b"hello",
      "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf"[:128],
    ),
  ]

  def test_blake2b_empty(self):
    """Test BLAKE2b with empty input."""
    self._extracted_from_test_blake2b_binary_data_3(b"")

  def test_blake2b_hello(self):
    """Test BLAKE2b with 'hello'."""
    self._extracted_from_test_blake2b_binary_data_3(b"hello")

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_blake2b_vs_hashlib(self, msg):
    """Verify BLAKE2b implementation matches hashlib output."""
    custom_result = blake2b(msg)
    hashlib_result = hashlib.blake2b(msg).hexdigest()
    assert custom_result == hashlib_result, f"Mismatch for: {msg!r}"

  def test_blake2b_large_input(self):
    """Test BLAKE2b with large input."""
    data = b"a" * 10000
    self._extracted_from_test_blake2b_binary_data_3(data)

  def test_blake2b_binary_data(self):
    """Test BLAKE2b with binary data."""
    data = bytes(range(256))
    self._extracted_from_test_blake2b_binary_data_3(data)

  @staticmethod
  def _extracted_from_test_blake2b_binary_data_3(arg0):
    result = blake2b(arg0)
    expected = hashlib.blake2b(arg0).hexdigest()
    assert result == expected

  def test_blake2b_different_digest_sizes(self):
    """Test BLAKE2b with different digest sizes."""
    for size in [1, 16, 32, 48, 64]:
      result = blake2b(b"hello", digest_size=size)
      expected = hashlib.blake2b(b"hello", digest_size=size).hexdigest()
      assert result == expected, f"Failed for digest_size={size}"
      assert len(result) == size * 2

  def test_blake2b_invalid_digest_size(self):
    """Test BLAKE2b with invalid digest sizes."""
    with pytest.raises(ValueError, match="digest_size must be between 1 and 64"):
      blake2b(b"hello", digest_size=0)
    with pytest.raises(ValueError, match="digest_size must be between 1 and 64"):
      blake2b(b"hello", digest_size=65)

  def test_blake2b_with_key(self):
    """Test BLAKE2b with key."""
    key = b"secret key"
    result = blake2b(b"hello", key=key)
    expected = hashlib.blake2b(b"hello", key=key).hexdigest()
    assert result == expected

  def test_blake2b_key_too_long(self):
    """Test BLAKE2b with key that's too long."""
    with pytest.raises(ValueError, match="key must be at most 64 bytes"):
      blake2b(b"hello", key=b"x" * 65)

  def test_blake2b_with_salt(self):
    """Test BLAKE2b with salt."""
    salt = b"saltsalt"  # 8 bytes
    result = blake2b(b"hello", salt=salt)
    expected = hashlib.blake2b(b"hello", salt=salt).hexdigest()
    assert result == expected

  def test_blake2b_salt_too_long(self):
    """Test BLAKE2b with salt that's too long."""
    with pytest.raises(ValueError, match="salt must be at most 16 bytes"):
      blake2b(b"hello", salt=b"x" * 17)

  def test_blake2b_with_person(self):
    """Test BLAKE2b with personalization."""
    person = b"personal"  # 8 bytes
    result = blake2b(b"hello", person=person)
    expected = hashlib.blake2b(b"hello", person=person).hexdigest()
    assert result == expected

  def test_blake2b_person_too_long(self):
    """Test BLAKE2b with personalization that's too long."""
    with pytest.raises(ValueError, match="person must be at most 16 bytes"):
      blake2b(b"hello", person=b"x" * 17)


class TestBlake2s:
  """Test BLAKE2s implementation against hashlib reference."""

  def test_blake2s_empty(self):
    """Test BLAKE2s with empty input."""
    result = blake2s(b"")
    expected = hashlib.blake2s(b"").hexdigest()
    assert result == expected

  def test_blake2s_hello(self):
    """Test BLAKE2s with 'hello'."""
    result = blake2s(b"hello")
    expected = hashlib.blake2s(b"hello").hexdigest()
    assert result == expected

  @pytest.mark.parametrize("msg", BYTE_TEST_CASES)
  def test_blake2s_vs_hashlib(self, msg):
    """Verify BLAKE2s implementation matches hashlib output."""
    custom_result = blake2s(msg)
    hashlib_result = hashlib.blake2s(msg).hexdigest()
    assert custom_result == hashlib_result, f"Mismatch for: {msg!r}"

  def test_blake2s_large_input(self):
    """Test BLAKE2s with large input."""
    data = b"a" * 10000
    custom_result = blake2s(data)
    hashlib_result = hashlib.blake2s(data).hexdigest()
    assert custom_result == hashlib_result

  def test_blake2s_binary_data(self):
    """Test BLAKE2s with binary data."""
    data = bytes(range(256))
    custom_result = blake2s(data)
    hashlib_result = hashlib.blake2s(data).hexdigest()
    assert custom_result == hashlib_result

  def test_blake2s_different_digest_sizes(self):
    """Test BLAKE2s with different digest sizes."""
    for size in [1, 16, 24, 32]:
      result = blake2s(b"hello", digest_size=size)
      expected = hashlib.blake2s(b"hello", digest_size=size).hexdigest()
      assert result == expected, f"Failed for digest_size={size}"
      assert len(result) == size * 2

  def test_blake2s_invalid_digest_size(self):
    """Test BLAKE2s with invalid digest sizes."""
    with pytest.raises(ValueError, match="digest_size must be between 1 and 32"):
      blake2s(b"hello", digest_size=0)
    with pytest.raises(ValueError, match="digest_size must be between 1 and 32"):
      blake2s(b"hello", digest_size=33)

  def test_blake2s_with_key(self):
    """Test BLAKE2s with key."""
    key = b"secret"
    result = blake2s(b"hello", key=key)
    expected = hashlib.blake2s(b"hello", key=key).hexdigest()
    assert result == expected

  def test_blake2s_key_too_long(self):
    """Test BLAKE2s with key that's too long."""
    with pytest.raises(ValueError, match="key must be at most 32 bytes"):
      blake2s(b"hello", key=b"x" * 33)

  def test_blake2s_with_salt(self):
    """Test BLAKE2s with salt."""
    salt = b"salt"  # 4 bytes
    result = blake2s(b"hello", salt=salt)
    expected = hashlib.blake2s(b"hello", salt=salt).hexdigest()
    assert result == expected

  def test_blake2s_salt_too_long(self):
    """Test BLAKE2s with salt that's too long."""
    with pytest.raises(ValueError, match="salt must be at most 8 bytes"):
      blake2s(b"hello", salt=b"x" * 9)

  def test_blake2s_with_person(self):
    """Test BLAKE2s with personalization."""
    person = b"pers"  # 4 bytes
    result = blake2s(b"hello", person=person)
    expected = hashlib.blake2s(b"hello", person=person).hexdigest()
    assert result == expected

  def test_blake2s_person_too_long(self):
    """Test BLAKE2s with personalization that's too long."""
    with pytest.raises(ValueError, match="person must be at most 8 bytes"):
      blake2s(b"hello", person=b"x" * 9)
