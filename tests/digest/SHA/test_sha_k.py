"""Tests for SHA-256 K table generation and verification.

Verifies that generate_sha2_k_table, verify_k_table, and print_k_table
produce correct constants per FIPS 180-4.
"""

from __future__ import annotations

from crypt.digest.SHA.sha_k import generate_sha2_k_table, print_k_table, verify_k_table


class TestGenerateSHA2KTable:
  """Tests for the generate_sha2_k_table function."""

  def test_k_table_has_64_entries(self):
    k_table = generate_sha2_k_table()
    assert len(k_table) == 64

  def test_k_table_matches_fips_180_4_standard(self):
    expected = [
      0x428A2F98,
      0x71374491,
      0xB5C0FBCF,
      0xE9B5DBA5,
      0x3956C25B,
      0x59F111F1,
      0x923F82A4,
      0xAB1C5ED5,
      0xD807AA98,
      0x12835B01,
      0x243185BE,
      0x550C7DC3,
      0x72BE5D74,
      0x80DEB1FE,
      0x9BDC06A7,
      0xC19BF174,
      0xE49B69C1,
      0xEFBE4786,
      0x0FC19DC6,
      0x240CA1CC,
      0x2DE92C6F,
      0x4A7484AA,
      0x5CB0A9DC,
      0x76F988DA,
      0x983E5152,
      0xA831C66D,
      0xB00327C8,
      0xBF597FC7,
      0xC6E00BF3,
      0xD5A79147,
      0x06CA6351,
      0x14292967,
      0x27B70A85,
      0x2E1B2138,
      0x4D2C6DFC,
      0x53380D13,
      0x650A7354,
      0x766A0ABB,
      0x81C2C92E,
      0x92722C85,
      0xA2BFE8A1,
      0xA81A664B,
      0xC24B8B70,
      0xC76C51A3,
      0xD192E819,
      0xD6990624,
      0xF40E3585,
      0x106AA070,
      0x19A4C116,
      0x1E376C08,
      0x2748774C,
      0x34B0BCB5,
      0x391C0CB3,
      0x4ED8AA4A,
      0x5B9CCA4F,
      0x682E6FF3,
      0x748F82EE,
      0x78A5636F,
      0x84C87814,
      0x8CC70208,
      0x90BEFFFA,
      0xA4506CEB,
      0xBEF9A3F7,
      0xC67178F2,
    ]
    k_table = generate_sha2_k_table()
    assert k_table == expected

  def test_first_k_value(self):
    k_table = generate_sha2_k_table()
    assert k_table[0] == 0x428A2F98

  def test_last_k_value(self):
    k_table = generate_sha2_k_table()
    assert k_table[63] == 0xC67178F2

  def test_all_values_are_32bit(self):
    k_table = generate_sha2_k_table()
    assert all(0 <= k <= 0xFFFFFFFF for k in k_table)


class TestVerifyKTable:
  """Tests for the verify_k_table function."""

  def test_verify_k_table_returns_true(self):
    assert verify_k_table() is True

  def test_verify_k_table_failure_path(self, monkeypatch):
    """Test verify_k_table failure path prints mismatches."""
    from crypt.digest.SHA import sha_k

    original_generate = sha_k.generate_sha2_k_table

    def bad_generate():
      table = original_generate()
      # Corrupt one value to trigger failure path
      table[0] = 0xDEADBEEF
      return table

    monkeypatch.setattr(sha_k, "generate_sha2_k_table", bad_generate)
    result = verify_k_table()
    assert result is False


class TestPrintKTable:
  """Tests for the print_k_table function."""

  def test_print_k_table_no_crash(self):
    print_k_table()
