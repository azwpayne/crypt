# @author  : azwpayne(https://github.com/azwpayne)
# @name    : chacha20_poly1305.py
# @time    : 2026/03/30
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8)
"""
ChaCha20-Poly1305 is an Authenticated Encryption with Associated Data (AEAD)
construction that combines the ChaCha20 stream cipher with the Poly1305
message authentication code.

It provides both confidentiality (via ChaCha20 encryption) and authenticity
(via Poly1305 MAC) in a single operation. Widely used in TLS 1.3, WireGuard,
and other modern protocols.

Reference: RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols, Section 2.8
"""

import struct
from crypt.digest.poly1305 import poly1305_mac
from crypt.encrypt.symmetric_encrypt.stream_cipher.chacha20 import (
  chacha20_block,
  chacha20_encrypt,
)


def _pad16(data: bytes) -> bytes:
  """Pad data to a 16-byte boundary with zero bytes."""
  remainder = len(data) % 16
  if remainder == 0:
    return data
  return data + b"\x00" * (16 - remainder)


def _construct_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
  """
  Construct the Poly1305 input data per RFC 8439 Section 2.8.

  Format: pad(AAD) || pad(CT) || len(AAD) || len(CT)
  where lengths are 64-bit little-endian integers.
  """
  return (
    _pad16(aad)
    + _pad16(ciphertext)
    + struct.pack("<Q", len(aad))
    + struct.pack("<Q", len(ciphertext))
  )


def chacha20_poly1305_encrypt(
  key: bytes,
  nonce: bytes,
  plaintext: bytes,
  aad: bytes = b"",
) -> bytes:
  """
  Encrypt and authenticate using ChaCha20-Poly1305 AEAD.

  Args:
      key: 32-byte encryption key.
      nonce: 12-byte nonce (must be unique per key).
      plaintext: Data to encrypt.
      aad: Additional authenticated data (not encrypted, but authenticated).

  Returns:
      Ciphertext concatenated with a 16-byte authentication tag.

  Raises:
      ValueError: If key is not 32 bytes or nonce is not 12 bytes.
  """
  if len(key) != 32:
    msg = f"Key must be 32 bytes, got {len(key)}"
    raise ValueError(msg)
  if len(nonce) != 12:
    msg = f"Nonce must be 12 bytes, got {len(nonce)}"
    raise ValueError(msg)

  # Step 1: Generate Poly1305 one-time key from ChaCha20 block at counter=0
  poly1305_key = chacha20_block(key, 0, nonce)[:32]

  # Step 2: Encrypt plaintext with ChaCha20 starting at counter=1
  ciphertext = chacha20_encrypt(key, nonce, 1, plaintext)

  # Step 3: Construct MAC input data
  mac_data = _construct_mac_data(aad, ciphertext)

  # Step 4: Compute Poly1305 tag
  tag = poly1305_mac(poly1305_key, mac_data)

  # Step 5: Return ciphertext || tag
  return ciphertext + tag


def chacha20_poly1305_decrypt(
  key: bytes,
  nonce: bytes,
  ciphertext_with_tag: bytes,
  aad: bytes = b"",
) -> bytes:
  """
  Verify and decrypt using ChaCha20-Poly1305 AEAD.

  Args:
      key: 32-byte encryption key.
      nonce: 12-byte nonce used during encryption.
      ciphertext_with_tag: Ciphertext concatenated with 16-byte tag.
      aad: Additional authenticated data (must match encryption).

  Returns:
      Decrypted plaintext.

  Raises:
      ValueError: If key is not 32 bytes, nonce is not 12 bytes,
                  or ciphertext_with_tag is too short.
      AuthenticationError: If the authentication tag is invalid.
  """
  if len(key) != 32:
    msg = f"Key must be 32 bytes, got {len(key)}"
    raise ValueError(msg)
  if len(nonce) != 12:
    msg = f"Nonce must be 12 bytes, got {len(nonce)}"
    raise ValueError(msg)
  if len(ciphertext_with_tag) < 16:
    msg = "Ciphertext must be at least 16 bytes (tag length)"
    raise ValueError(msg)

  # Split ciphertext and tag
  ciphertext = ciphertext_with_tag[:-16]
  received_tag = ciphertext_with_tag[-16:]

  # Step 1: Generate Poly1305 one-time key from ChaCha20 block at counter=0
  poly1305_key = chacha20_block(key, 0, nonce)[:32]

  # Step 2: Construct MAC input data
  mac_data = _construct_mac_data(aad, ciphertext)

  # Step 3: Compute expected tag
  expected_tag = poly1305_mac(poly1305_key, mac_data)

  # Step 4: Constant-time tag verification
  if not _constant_time_compare(received_tag, expected_tag):
    msg = "Authentication tag verification failed"
    raise AuthenticationError(msg)

  # Step 5: Decrypt ciphertext with ChaCha20 starting at counter=1
  return chacha20_encrypt(key, nonce, 1, ciphertext)


def _constant_time_compare(a: bytes, b: bytes) -> bool:
  """Compare two byte strings in constant time to prevent timing attacks."""
  if len(a) != len(b):
    return False
  result = 0
  for x, y in zip(a, b, strict=False):
    result |= x ^ y
  return result == 0


class AuthenticationError(Exception):
  """Raised when authentication tag verification fails."""
