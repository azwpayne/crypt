"""Tests for AES-OCB3 (RFC 7253) implementation.

Validates encrypt/decrypt roundtrip, tag verification, and edge cases.
"""

from __future__ import annotations

import re
from crypt.encrypt.symmetric_encrypt.modes.ocb import ocb_decrypt, ocb_encrypt

import pytest

AES128_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class TestOCB3AES128:
  """Tests for AES-128-OCB3."""

  @pytest.mark.parametrize(
    ("plaintext", "aad"),
    [
      (b"", b""),
      (b"\x00", b""),
      (b"Hello, OCB3!", b""),
      (b"", b"aad"),
      (b"Hello", b"authenticated data"),
      (bytes(range(15)), b"aad"),
    ],
  )
  def test_roundtrip(self, plaintext: bytes, aad: bytes) -> None:
    """Test encrypt then decrypt roundtrip."""
    nonce = bytes.fromhex("000102030405060708090a0b")
    ct = ocb_encrypt(AES128_KEY, nonce, plaintext, aad)
    pt = ocb_decrypt(AES128_KEY, nonce, ct, aad)
    assert pt == plaintext

  def test_different_nonces(self) -> None:
    """Test that different nonces produce different ciphertexts."""
    plaintext = b"same message"
    ct1 = ocb_encrypt(AES128_KEY, b"\x00" * 12, plaintext, b"")
    ct2 = ocb_encrypt(AES128_KEY, b"\x01" * 12, plaintext, b"")
    assert ct1 != ct2

  def test_different_aad(self) -> None:
    """Test that different AAD produces different tags."""
    nonce = bytes.fromhex("000102030405060708090a0b")
    plaintext = b"same message"
    ct1 = ocb_encrypt(AES128_KEY, nonce, plaintext, b"aad1")
    ct2 = ocb_encrypt(AES128_KEY, nonce, plaintext, b"aad2")
    assert ct1 != ct2

  def test_tag_length_is_16(self) -> None:
    """Test that tag is always 16 bytes."""
    nonce = bytes.fromhex("000102030405060708090a0b")
    ct_empty = ocb_encrypt(AES128_KEY, nonce, b"", b"")
    ct_1byte = ocb_encrypt(AES128_KEY, nonce, b"\x00", b"")
    assert len(ct_empty) == 16
    assert len(ct_1byte) == 17

  def test_tampered_ciphertext(self) -> None:
    """Test that tampered ciphertext is rejected."""
    key = AES128_KEY
    nonce = bytes.fromhex("000102030405060708090a0b")
    plaintext = b"Hello, OCB3!"

    ct = ocb_encrypt(key, nonce, plaintext, b"")
    tampered = bytearray(ct)
    tampered[0] ^= 0x01

    with pytest.raises(ValueError, match=re.compile("authentication", re.IGNORECASE)):
      ocb_decrypt(key, nonce, bytes(tampered), b"")

  def test_tampered_aad(self) -> None:
    """Test that tampered AAD is rejected."""
    key = AES128_KEY
    nonce = bytes.fromhex("000102030405060708090a0b")

    ct = ocb_encrypt(key, nonce, b"data", b"original aad")

    with pytest.raises(ValueError, match=re.compile("authentication", re.IGNORECASE)):
      ocb_decrypt(key, nonce, ct, b"tampered aad")

  def test_empty_plaintext_with_aad(self) -> None:
    """Test empty plaintext with non-empty AAD."""
    key = AES128_KEY
    nonce = bytes.fromhex("000102030405060708090a0b")
    aad = b"some authenticated data"

    ct = ocb_encrypt(key, nonce, b"", aad)
    assert len(ct) == 16  # tag only

    pt = ocb_decrypt(key, nonce, ct, aad)
    assert pt == b""

  def test_long_nonce_rejected(self) -> None:
    """Test that nonces longer than 15 bytes are rejected."""
    with pytest.raises((ValueError, OverflowError)):
      ocb_encrypt(AES128_KEY, b"\x00" * 16, b"data", b"")


class TestOCBEdgeCases:
  def test_ntz_zero(self):
    from crypt.encrypt.symmetric_encrypt.modes.ocb import _ntz

    assert _ntz(0) == 128
    assert _ntz(1) == 0
    assert _ntz(2) == 1
    assert _ntz(4) == 2
    assert _ntz(8) == 3

  def test_constant_time_compare(self):
    from crypt.encrypt.symmetric_encrypt.modes.ocb import _constant_time_compare

    assert _constant_time_compare(b"abc", b"abcd") is False
    assert _constant_time_compare(b"", b"") is True
    assert _constant_time_compare(b"same", b"same") is True
    assert _constant_time_compare(b"same", b"dame") is False

  def test_invalid_tag_len(self):
    with pytest.raises(ValueError, match="tag_len must be between"):
      ocb_encrypt(AES128_KEY, b"\x00" * 12, b"data", b"", tag_len=0)
    with pytest.raises(ValueError, match="tag_len must be between"):
      ocb_encrypt(AES128_KEY, b"\x00" * 12, b"data", b"", tag_len=17)

  def test_ciphertext_too_short(self):
    with pytest.raises(ValueError, match="Ciphertext too short"):
      ocb_decrypt(AES128_KEY, b"\x00" * 12, b"\x00" * 5, b"")
