# GCM (Galois/Counter Mode) AEAD - STUB IMPLEMENTATION
"""
Galois/Counter Mode (GCM) is an authenticated encryption mode.
It provides both confidentiality and authenticity using CTR mode
for encryption and GHASH for authentication.

WARNING: This is a STUB implementation that uses SHA-256 keystream
instead of proper CTR mode. Do not use for production cryptography.

Reference: NIST SP 800-38D
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


def _generate_keystream(key: bytes, iv: bytes, length: int) -> bytes:
  """Generate a keystream using key and IV (stub implementation).

  NOTE: This uses SHA-256 hash instead of proper CTR mode encryption.
  A production implementation should use the block cipher in CTR mode.
  """
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
  """Encrypt using GCM mode (STUB).

  WARNING: This is a simplified placeholder implementation.
  Real GCM requires proper CTR mode and GHASH authentication.

  Args:
      key: Encryption key
      iv: Initialization vector (nonce)
      plaintext: Data to encrypt
      aad: Additional authenticated data
      block_cipher: Block cipher function (NOT IMPLEMENTED)

  Returns:
      Tuple of (ciphertext, authentication_tag)

  Raises:
      NotImplementedError: If block_cipher is provided
  """
  if block_cipher is None:
    # Use hash-based keystream (stub)
    keystream = _generate_keystream(key, iv, len(plaintext))
    ciphertext = _xor_bytes(plaintext, keystream)
    # Generate a simple tag based on AAD, IV, and ciphertext
    tag_input = aad + iv + ciphertext + key
    tag = hashlib.sha256(tag_input).digest()[:16]
    return ciphertext, tag

  msg = "Block cipher-based GCM not yet implemented"
  raise NotImplementedError(msg)


def gcm_decrypt(
  key: bytes,
  iv: bytes,
  ciphertext: bytes,
  tag: bytes,
  aad: bytes = b"",
  **kwargs: object,
) -> bytes | None:
  """Decrypt using GCM mode (STUB).

  WARNING: This is a simplified placeholder implementation.

  Args:
      key: Encryption key
      iv: Initialization vector (nonce)
      ciphertext: Data to decrypt
      tag: Authentication tag
      aad: Additional authenticated data
      block_cipher: Block cipher function (NOT IMPLEMENTED, via kwargs)

  Returns:
      Decrypted plaintext if authentication succeeds, None otherwise

  Raises:
      NotImplementedError: If block_cipher is provided
  """
  block_cipher = kwargs.get("block_cipher")
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
