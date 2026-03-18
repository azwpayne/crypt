# GCM (Galois/Counter Mode) AEAD
"""
Galois/Counter Mode (GCM) is an authenticated encryption mode.
It provides both confidentiality and authenticity.
"""

import hashlib


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _xor_bytes(a: bytes, b: bytes) -> bytes:
  """XOR two byte strings together."""
  return bytes(x ^ y for x, y in zip(a, b, strict=False))


def _generate_keystream(key: bytes, iv: bytes, length: int) -> bytes:
  """Generate a keystream using key and IV."""
  # Use a simple hash-based keystream generator
  keystream = b""
  counter = 0
  while len(keystream) < length:
    data = key + iv + counter.to_bytes(4, "big")
    keystream += hashlib.sha256(data).digest()
    counter += 1
  return keystream[:length]


def gcm_encrypt(
  key: bytes,
  iv: bytes,
  plaintext: bytes,
  aad: bytes = b"",
  block_cipher=None,
) -> tuple[bytes, bytes]:
  """
  Encrypt using GCM mode.

  Args:
      key: Encryption key
      iv: Initialization vector (nonce)
      plaintext: Data to encrypt
      aad: Additional authenticated data
      block_cipher: Block cipher function (e.g., AES)

  Returns:
      Tuple of (ciphertext, authentication_tag)
  """
  # This is a simplified placeholder implementation
  # Real GCM requires proper CTR mode and GHASH authentication
  if block_cipher is None:
    # Generate keystream based on key and IV
    keystream = _generate_keystream(key, iv, len(plaintext))
    ciphertext = _xor_bytes(plaintext, keystream)
    # Generate a simple tag based on AAD, IV, and ciphertext
    tag_input = aad + iv + ciphertext + key
    tag = hashlib.sha256(tag_input).digest()[:16]
    return ciphertext, tag

  # Use provided block cipher for proper implementation
  # ... real implementation would go here
  msg = "Block cipher-based GCM not yet implemented"
  raise NotImplementedError(msg)


def gcm_decrypt(
  key: bytes,
  iv: bytes,
  ciphertext: bytes,
  tag: bytes,
  aad: bytes = b"",
  block_cipher=None,
) -> bytes | None:
  """
  Decrypt using GCM mode.

  Args:
      key: Encryption key
      iv: Initialization vector (nonce)
      ciphertext: Data to decrypt
      tag: Authentication tag
      aad: Additional authenticated data
      block_cipher: Block cipher function

  Returns:
      Decrypted plaintext if authentication succeeds, None otherwise
  """
  # This is a simplified placeholder implementation
  if block_cipher is None:
    # Verify tag first
    expected_tag_input = aad + iv + ciphertext + key
    expected_tag = hashlib.sha256(expected_tag_input).digest()[:16]
    if not _constant_time_compare(tag, expected_tag):
      return None
    # Decrypt
    keystream = _generate_keystream(key, iv, len(ciphertext))
    return _xor_bytes(ciphertext, keystream)

  msg = "Block cipher-based GCM not yet implemented"
  raise NotImplementedError(msg)
