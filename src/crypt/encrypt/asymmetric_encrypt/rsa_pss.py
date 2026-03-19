"""Pure Python implementation of RSA-PSS signature scheme.

RSA-PSS (Probabilistic Signature Scheme) is defined in PKCS#1 v2.2 (RFC 8017).
It provides secure digital signatures with salt for randomization.

This implementation is for educational purposes only.
"""

from __future__ import annotations

import hashlib
import os
from typing import Protocol


class HashFunc(Protocol):
  """Protocol for hash functions like hashlib.sha256."""

  def __call__(self, data: bytes = b"") -> hashlib._Hash: ...


def mgf1(seed: bytes, length: int, hash_func: HashFunc = hashlib.sha256) -> bytes:
  """Mask Generation Function 1.

  Args:
      seed: Seed for mask generation
      length: Desired length of output
      hash_func: Hash function to use

  Returns:
      Generated mask
  """
  if length > (2**32) * hash_func().digest_size:
    msg = "Mask too long"
    raise ValueError(msg)

  output = b""
  counter = 0
  while len(output) < length:
    c = counter.to_bytes(4, "big")
    output += hash_func(seed + c).digest()
    counter += 1

  return output[:length]


def _emsa_pss_encode(
  message: bytes,
  em_bits: int,
  salt_len: int,
  hash_func: HashFunc,
) -> bytes:
  """EMSA-PSS-ENCODE operation.

  Args:
      message: Message to encode
      em_bits: Max bits in encoded message
      salt_len: Length of salt in bytes
      hash_func: Hash function to use

  Returns:
      Encoded message
  """
  hash_len = hash_func().digest_size

  if em_bits < 8 * hash_len + 8 * salt_len + 9:
    msg = "Encoding error"
    raise ValueError(msg)

  em_len = (em_bits + 7) // 8

  # Hash message
  m_hash = hash_func(message).digest()

  # Generate random salt
  salt = os.urandom(salt_len)

  # Construct M' = 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 || m_hash || salt
  m_prime = b"\x00" * 8 + m_hash + salt

  # Hash M'
  h = hash_func(m_prime).digest()

  # Construct DB = PS || 0x01 || salt
  # where PS is padding of zeros
  ps_len = em_len - salt_len - hash_len - 2
  db = b"\x00" * ps_len + b"\x01" + salt

  # Mask DB
  db_mask = mgf1(h, len(db), hash_func)
  masked_db = bytes(x ^ y for x, y in zip(db, db_mask, strict=False))

  # Clear leading bits
  bits_to_clear = 8 * em_len - em_bits
  masked_db = (masked_db[0] & ((1 << (8 - bits_to_clear)) - 1)).to_bytes(
    1, "big"
  ) + masked_db[1:]

  # EM = masked_db || h || 0xbc
  return masked_db + h + b"\xbc"


def _emsa_pss_verify(
  message: bytes,
  em: bytes,
  em_bits: int,
  salt_len: int,
  hash_func: HashFunc,
) -> bool:
  """EMSA-PSS-VERIFY operation.

  Args:
      message: Original message
      em: Encoded message to verify
      em_bits: Max bits in encoded message
      salt_len: Length of salt in bytes
      hash_func: Hash function to use

  Returns:
      True if valid, False otherwise
  """
  hash_len = hash_func().digest_size
  em_len = (em_bits + 7) // 8

  # Basic length and format checks
  if em_bits < 8 * hash_len + 8 * salt_len + 9 or len(em) != em_len or em[-1] != 0xBC:
    return False

  # Split EM
  masked_db = em[: em_len - hash_len - 1]
  h = em[em_len - hash_len - 1 : -1]

  # Check leading bits are zero
  bits_to_clear = 8 * em_len - em_bits
  if masked_db[0] >> (8 - bits_to_clear) != 0:
    return False

  # Unmask DB
  db_mask = mgf1(h, len(masked_db), hash_func)
  db = bytes(x ^ y for x, y in zip(masked_db, db_mask, strict=False))

  # Clear leading bits
  db = (db[0] & ((1 << (8 - bits_to_clear)) - 1)).to_bytes(1, "big") + db[1:]

  # Check padding
  ps_len = em_len - salt_len - hash_len - 2
  if db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 0x01:
    return False

  # Extract salt
  salt = db[ps_len + 1 :]

  # Reconstruct and verify
  m_hash = hash_func(message).digest()
  m_prime = b"\x00" * 8 + m_hash + salt
  h_prime = hash_func(m_prime).digest()

  return h == h_prime


def sign(
  message: bytes,
  private_key: tuple[int, int],
  salt_len: int | None = None,
  hash_func: HashFunc = hashlib.sha256,
) -> bytes:
  """Sign message using RSA-PSS.

  Args:
      message: Message to sign
      private_key: (d, n) tuple where d is private exponent, n is modulus
      salt_len: Salt length in bytes (default: hash length)
      hash_func: Hash function to use (default: sha256)

  Returns:
      Signature bytes
  """
  d, n = private_key

  if salt_len is None:
    salt_len = hash_func().digest_size

  # Get bit length of modulus
  em_bits = n.bit_length() - 1

  # Encode message
  em = _emsa_pss_encode(message, em_bits, salt_len, hash_func)

  # Convert to integer
  m = int.from_bytes(em, "big")

  if m >= n:
    msg = "Message too long"
    raise ValueError(msg)

  # RSA signature: s = m^d mod n
  s = pow(m, d, n)

  # Convert to bytes
  sig_len = (n.bit_length() + 7) // 8
  return s.to_bytes(sig_len, "big")


def verify(
  signature: bytes,
  message: bytes,
  public_key: tuple[int, int],
  salt_len: int | None = None,
  hash_func: HashFunc = hashlib.sha256,
) -> bool:
  """Verify RSA-PSS signature.

  Args:
      signature: Signature bytes
      message: Original message
      public_key: (e, n) tuple where e is public exponent, n is modulus
      salt_len: Salt length (default: hash length)
      hash_func: Hash function used for signing

  Returns:
      True if valid, False otherwise
  """
  e, n = public_key

  if salt_len is None:
    salt_len = hash_func().digest_size

  # Get bit length
  em_bits = n.bit_length() - 1
  sig_len = (n.bit_length() + 7) // 8

  if len(signature) != sig_len:
    return False

  # Convert signature to integer
  s = int.from_bytes(signature, "big")

  if s >= n:
    return False

  # RSA verification: m = s^e mod n
  m = pow(s, e, n)

  # Convert to bytes
  em_len = (em_bits + 7) // 8
  em = m.to_bytes(em_len, "big")

  # Verify encoding
  return _emsa_pss_verify(message, em, em_bits, salt_len, hash_func)
