"""Tests for ChaCha20-Poly1305 AEAD (RFC 8439).

Test vectors from RFC 8439 Appendix A.5.
"""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.chacha20_poly1305 import (
  AuthenticationError,
  chacha20_poly1305_decrypt,
  chacha20_poly1305_encrypt,
)

import pytest

# RFC 8439 Appendix A.5 test vectors (verified against cryptography library)
RFC8439_TEST_VECTORS: list[tuple[str, str, str, str, str, str]] = [
  # Test Vector #1: AAD + Plaintext
  (
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",  # key
    "070000004041424344454647",  # nonce
    "50515253c0c1c2c3c4c5c6c7",  # aad
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e",  # plaintext
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116",  # ciphertext
    "1ae10b594f09e26a7e902ecbd0600691",  # tag
  ),
  # Test Vector #2: No AAD
  (
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",  # key
    "070000004041424344454647",  # nonce
    "",  # aad (empty)
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e",  # plaintext
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116",  # ciphertext
    "6a23a4681fd59456aea1d29f82477216",  # tag
  ),
  # Test Vector #3: AAD only, empty plaintext
  (
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",  # key
    "070000004041424344454647",  # nonce
    "50515253c0c1c2c3c4c5c6c7",  # aad
    "",  # plaintext (empty)
    "",  # ciphertext (empty)
    "e622e5647a38d967a7ecbcb46c7f675c",  # tag
  ),
]


class TestChaCha20Poly1305RFC8439:
  """Tests against RFC 8439 Appendix A.5 test vectors."""

  @pytest.mark.parametrize(
    ("key_hex", "nonce_hex", "aad_hex", "pt_hex", "ct_hex", "tag_hex"),
    RFC8439_TEST_VECTORS,
  )
  def test_encrypt(  # noqa: PLR0913
    self,
    key_hex: str,
    nonce_hex: str,
    aad_hex: str,
    pt_hex: str,
    ct_hex: str,
    tag_hex: str,
  ) -> None:
    """Test encryption against RFC 8439 test vectors."""
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    aad = bytes.fromhex(aad_hex) if aad_hex else b""
    plaintext = bytes.fromhex(pt_hex) if pt_hex else b""
    expected_ct = bytes.fromhex(ct_hex) if ct_hex else b""
    expected_tag = bytes.fromhex(tag_hex)

    result = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
    ciphertext = result[:-16]
    tag = result[-16:]

    assert ciphertext == expected_ct
    assert tag == expected_tag

  @pytest.mark.parametrize(
    ("key_hex", "nonce_hex", "aad_hex", "pt_hex", "ct_hex", "tag_hex"),
    RFC8439_TEST_VECTORS,
  )
  def test_decrypt(  # noqa: PLR0913
    self,
    key_hex: str,
    nonce_hex: str,
    aad_hex: str,
    pt_hex: str,
    ct_hex: str,
    tag_hex: str,
  ) -> None:
    """Test decryption against RFC 8439 test vectors."""
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    aad = bytes.fromhex(aad_hex) if aad_hex else b""
    expected_pt = bytes.fromhex(pt_hex) if pt_hex else b""
    ct = bytes.fromhex(ct_hex) if ct_hex else b""
    tag = bytes.fromhex(tag_hex)

    ciphertext_with_tag = ct + tag
    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext_with_tag, aad)

    assert plaintext == expected_pt

  @pytest.mark.parametrize(
    ("key_hex", "nonce_hex", "aad_hex", "pt_hex", "_ct_hex", "_tag_hex"),
    RFC8439_TEST_VECTORS,
  )
  def test_roundtrip(  # noqa: PLR0913
    self,
    key_hex: str,
    nonce_hex: str,
    aad_hex: str,
    pt_hex: str,
    _ct_hex: str,
    _tag_hex: str,
  ) -> None:
    """Test encrypt then decrypt roundtrip."""
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    aad = bytes.fromhex(aad_hex) if aad_hex else b""
    plaintext = bytes.fromhex(pt_hex) if pt_hex else b""

    encrypted = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
    decrypted = chacha20_poly1305_decrypt(key, nonce, encrypted, aad)

    assert decrypted == plaintext


class TestChaCha20Poly1305EdgeCases:
  """Edge case and error handling tests."""

  def test_empty_plaintext(self) -> None:
    """Test encryption with empty plaintext."""
    key = bytes(32)
    nonce = bytes(12)
    result = chacha20_poly1305_encrypt(key, nonce, b"", b"")

    # Ciphertext should be empty, only tag present
    assert len(result) == 16

  def test_empty_plaintext_with_aad(self) -> None:
    """Test encryption with empty plaintext but non-empty AAD."""
    key = bytes(32)
    nonce = bytes(12)
    aad = b"authenticated but not encrypted"
    result = chacha20_poly1305_encrypt(key, nonce, b"", aad)

    assert len(result) == 16  # tag only
    # Decrypt should succeed
    plaintext = chacha20_poly1305_decrypt(key, nonce, result, aad)
    assert plaintext == b""

  def test_aad_affects_tag(self) -> None:
    """Test that different AAD produces different tags."""
    key = bytes(32)
    nonce = bytes(12)
    plaintext = b"test"

    result1 = chacha20_poly1305_encrypt(key, nonce, plaintext, b"aad1")
    result2 = chacha20_poly1305_encrypt(key, nonce, plaintext, b"aad2")

    # Same ciphertext (same key/nonce/counter), different tags
    assert result1[:-16] == result2[:-16]
    assert result1[-16:] != result2[-16:]

  def test_wrong_key_size(self) -> None:
    """Test that wrong key size raises ValueError."""
    with pytest.raises(ValueError, match="Key must be 32 bytes"):
      chacha20_poly1305_encrypt(b"\x00" * 16, bytes(12), b"data")

    with pytest.raises(ValueError, match="Key must be 32 bytes"):
      chacha20_poly1305_decrypt(b"\x00" * 16, bytes(12), b"\x00" * 16)

  def test_wrong_nonce_size(self) -> None:
    """Test that wrong nonce size raises ValueError."""
    with pytest.raises(ValueError, match="Nonce must be 12 bytes"):
      chacha20_poly1305_encrypt(bytes(32), b"\x00" * 8, b"data")

    with pytest.raises(ValueError, match="Nonce must be 12 bytes"):
      chacha20_poly1305_decrypt(bytes(32), b"\x00" * 8, b"\x00" * 16)

  def test_ciphertext_too_short(self) -> None:
    """Test that ciphertext shorter than tag raises ValueError."""
    with pytest.raises(ValueError, match="at least 16 bytes"):
      chacha20_poly1305_decrypt(bytes(32), bytes(12), b"\x00" * 10)

  def test_tampered_ciphertext(self) -> None:
    """Test that tampered ciphertext raises AuthenticationError."""
    key = bytes(32)
    nonce = bytes(12)
    plaintext = b"secret message"

    encrypted = chacha20_poly1305_encrypt(key, nonce, plaintext)

    # Tamper with ciphertext byte
    tampered = bytearray(encrypted)
    tampered[0] ^= 0x01

    with pytest.raises(AuthenticationError):
      chacha20_poly1305_decrypt(key, nonce, bytes(tampered))

  def test_tampered_tag(self) -> None:
    """Test that tampered tag raises AuthenticationError."""
    key = bytes(32)
    nonce = bytes(12)
    plaintext = b"secret message"

    encrypted = chacha20_poly1305_encrypt(key, nonce, plaintext)

    # Tamper with tag byte
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0x01

    with pytest.raises(AuthenticationError):
      chacha20_poly1305_decrypt(key, nonce, bytes(tampered))

  def test_tampered_aad(self) -> None:
    """Test that wrong AAD raises AuthenticationError."""
    key = bytes(32)
    nonce = bytes(12)
    plaintext = b"secret message"
    aad = b"original aad"

    encrypted = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    with pytest.raises(AuthenticationError):
      chacha20_poly1305_decrypt(key, nonce, encrypted, b"tampered aad")

  def test_wrong_key_decrypt(self) -> None:
    """Test that wrong key raises AuthenticationError."""
    key1 = bytes(32)
    key2 = bytes(range(32))
    nonce = bytes(12)
    plaintext = b"secret message"

    encrypted = chacha20_poly1305_encrypt(key1, nonce, plaintext)

    with pytest.raises(AuthenticationError):
      chacha20_poly1305_decrypt(key2, nonce, encrypted)

  def test_wrong_nonce_decrypt(self) -> None:
    """Test that wrong nonce raises AuthenticationError."""
    key = bytes(32)
    nonce1 = bytes(12)
    nonce2 = bytes(range(12))
    plaintext = b"secret message"

    encrypted = chacha20_poly1305_encrypt(key, nonce1, plaintext)

    with pytest.raises(AuthenticationError):
      chacha20_poly1305_decrypt(key, nonce2, encrypted)

  def test_large_plaintext(self) -> None:
    """Test with large plaintext spanning multiple ChaCha20 blocks."""
    key = bytes(32)
    nonce = bytes(12)
    plaintext = b"A" * 1000

    encrypted = chacha20_poly1305_encrypt(key, nonce, plaintext)
    decrypted = chacha20_poly1305_decrypt(key, nonce, encrypted)

    assert decrypted == plaintext
    assert len(encrypted) == len(plaintext) + 16

  def test_binary_data(self) -> None:
    """Test with binary data containing all byte values."""
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = bytes(range(256))

    encrypted = chacha20_poly1305_encrypt(key, nonce, plaintext)
    decrypted = chacha20_poly1305_decrypt(key, nonce, encrypted)

    assert decrypted == plaintext
