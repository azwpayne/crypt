"""Tests for SHA-256/SHA-512 initialization vector generation.

Verifies that generate_sha2_initialization_vector produces correct
initial hash values per FIPS 180-4.
"""

from __future__ import annotations

from crypt.digest.SHA.sha_iv import generate_sha2_initialization_vector

import pytest


class TestGenerateSHA2InitializationVector:
  """Tests for the generate_sha2_initialization_vector function."""

  def test_generate_sha256_iv_matches_fips_180_4(self):
    """Test SHA-256 IV values match FIPS 180-4 specification (first 8 of 16)."""
    expected = [
      0x6A09E667,
      0xBB67AE85,
      0x3C6EF372,
      0xA54FF53A,
      0x510E527F,
      0x9B05688C,
      0x1F83D9AB,
      0x5BE0CD19,
    ]
    result = generate_sha2_initialization_vector("SHA-256")
    assert result[:8] == expected

  def test_generate_sha512_iv_matches_fips_180_4(self):
    """Test SHA-512 IV values match FIPS 180-4 specification (first 8 of 16)."""
    expected = [
      0x6A09E667F3BCC908,
      0xBB67AE8584CAA73B,
      0x3C6EF372FE94F82B,
      0xA54FF53A5F1D36F1,
      0x510E527FADE682D1,
      0x9B05688C2B3E6C1F,
      0x1F83D9ABFB41BD6B,
      0x5BE0CD19137E2179,
    ]
    result = generate_sha2_initialization_vector("SHA-512")
    assert result[:8] == expected

  def test_default_algorithm_is_sha256(self):
    """Test that calling without arguments defaults to SHA-256."""
    expected = [
      0x6A09E667,
      0xBB67AE85,
      0x3C6EF372,
      0xA54FF53A,
      0x510E527F,
      0x9B05688C,
      0x1F83D9AB,
      0x5BE0CD19,
    ]
    result = generate_sha2_initialization_vector()
    assert result[:8] == expected

  def test_unsupported_algorithm_raises_value_error(self):
    """Test that unsupported algorithms raise ValueError."""
    with pytest.raises(ValueError, match="不支持的算法"):
      generate_sha2_initialization_vector("SHA-1")

  def test_non_string_algorithm_raises_type_error(self):
    """Test that non-string algorithm raises TypeError."""
    with pytest.raises(TypeError, match="algorithm 参数必须是字符串"):
      generate_sha2_initialization_vector(123)

  def test_returns_exactly_16_values(self):
    """Test that the function returns 16 initialization values (from 16 primes)."""
    result_256 = generate_sha2_initialization_vector("SHA-256")
    result_512 = generate_sha2_initialization_vector("SHA-512")
    assert len(result_256) == 16
    assert len(result_512) == 16
