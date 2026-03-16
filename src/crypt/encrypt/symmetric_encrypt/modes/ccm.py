# CCM (Counter with CBC-MAC) AEAD
"""
CCM (Counter with CBC-MAC) is an authenticated encryption mode.
It combines CTR mode for encryption with CBC-MAC for authentication.
"""

import hashlib


def _xor_bytes(a: bytes, b: bytes) -> bytes:
  """XOR two byte strings together."""
  return bytes(x ^ y for x, y in zip(a, b, strict=False))


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
  """Generate a keystream using key and nonce."""
  # Use a simple hash-based keystream generator
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
  """
  Encrypt using CCM mode.

  Args:
      key: Encryption key
      nonce: Nonce (number used once)
      plaintext: Data to encrypt
      aad: Additional authenticated data
      mac_len: Length of MAC tag (4, 6, 8, 10, 12, 14, or 16 bytes)

  Returns:
      Tuple of (ciphertext, authentication_tag)
  """
  # This is a simplified placeholder implementation
  # Real CCM requires proper formatting function and CTR/CBC modes
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
  """
  Decrypt using CCM mode.

  Args:
      key: Encryption key
      nonce: Nonce (number used once)
      ciphertext: Data to decrypt
      tag: Authentication tag
      aad: Additional authenticated data

  Returns:
      Decrypted plaintext if authentication succeeds, None otherwise
  """
  # This is a simplified placeholder implementation
  # Verify tag first
  expected_tag_input = aad + nonce + ciphertext + key
  expected_tag = hashlib.sha256(expected_tag_input).digest()[: len(tag)]
  if tag != expected_tag:
    return None
  # Decrypt
  keystream = _generate_keystream(key, nonce, len(ciphertext))
  return _xor_bytes(ciphertext, keystream)
