# CCM (Counter with CBC-MAC) AEAD - STUB IMPLEMENTATION
"""
CCM (Counter with CBC-MAC) is an authenticated encryption mode.
It combines CTR mode for encryption with CBC-MAC for authentication.

WARNING: This is a STUB implementation that uses SHA-256 keystream
instead of proper CTR mode. Do not use for production cryptography.

Reference: RFC 3610, NIST SP 800-38C
"""

import hashlib


def _constant_time_compare(a: bytes, b: bytes) -> bool:
  """Compare two byte strings in constant time to prevent timing attacks."""
  if len(a) != len(b):
    return False
  result = 0
  for x, y in zip(a, b, strict=False):
    result |= x ^ y
  return result == 0


def _xor_bytes(a: bytes, b: bytes) -> bytes:
  """XOR two byte strings together."""
  return bytes(x ^ y for x, y in zip(a, b, strict=False))


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
  """Generate a keystream using key and nonce (stub implementation).

  NOTE: This uses SHA-256 hash instead of proper CTR mode encryption.
  A production implementation should use the block cipher in CTR mode.
  """
  keystream = b""
  counter = 0
  while len(keystream) < length:
    data = key + nonce + counter.to_bytes(4, "big")
    keystream += hashlib.sha256(data).digest()
    counter += 1
  return keystream[:length]


def ccm_encrypt(
  key: bytes,
  nonce: bytes,
  plaintext: bytes,
  aad: bytes = b"",
  mac_len: int = 16,
) -> tuple[bytes, bytes]:
  """Encrypt using CCM mode (STUB).

  WARNING: This is a simplified placeholder implementation.
  Real CCM requires proper formatting function and CTR/CBC modes.

  Args:
      key: Encryption key
      nonce: Nonce (number used once)
      plaintext: Data to encrypt
      aad: Additional authenticated data
      mac_len: Length of MAC tag (4, 6, 8, 10, 12, 14, or 16 bytes)

  Returns:
      Tuple of (ciphertext, authentication_tag)
  """
  # Use hash-based keystream (stub)
  keystream = _generate_keystream(key, nonce, len(plaintext))
  ciphertext = _xor_bytes(plaintext, keystream)
  # Generate a simple tag based on AAD, nonce, and ciphertext
  tag_input = aad + nonce + ciphertext + key
  tag = hashlib.sha256(tag_input).digest()[:mac_len]
  return ciphertext, tag


def ccm_decrypt(
  key: bytes,
  nonce: bytes,
  ciphertext: bytes,
  tag: bytes,
  aad: bytes = b"",
) -> bytes | None:
  """Decrypt using CCM mode (STUB).

  WARNING: This is a simplified placeholder implementation.

  Args:
      key: Encryption key
      nonce: Nonce (number used once)
      ciphertext: Data to decrypt
      tag: Authentication tag
      aad: Additional authenticated data

  Returns:
      Decrypted plaintext if authentication succeeds, None otherwise
  """
  # Verify tag first
  expected_tag_input = aad + nonce + ciphertext + key
  expected_tag = hashlib.sha256(expected_tag_input).digest()[: len(tag)]
  if not _constant_time_compare(tag, expected_tag):
    return None
  # Decrypt
  keystream = _generate_keystream(key, nonce, len(ciphertext))
  return _xor_bytes(ciphertext, keystream)
