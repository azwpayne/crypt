"""
RSA asymmetric encryption implementation.

This module provides basic RSA functionality for educational purposes:
- Key pair generation
- Encryption/decryption
- Signing/verification
"""

import random
import secrets


def is_prime(n: int, k: int = 10) -> bool:
  """Miller-Rabin primality test."""
  if n < 2:
    return False
  if n in {2, 3}:
    return True
  if n % 2 == 0:
    return False

  # Write n-1 as 2^r * d
  r, d = 0, n - 1
  while d % 2 == 0:
    r += 1
    d //= 2

  # Witness loop
  for _ in range(k):
    a = secrets.randbelow(n - 3) + 2
    x = pow(a, d, n)
    if x in [1, n - 1]:
      continue
    for _ in range(r - 1):
      x = pow(x, 2, n)
      if x == n - 1:
        break
    else:
      return False
  return True


def generate_prime(bits: int) -> int:
  """Generate a random prime number with the specified number of bits."""
  while True:
    # Generate random odd number with exact bit length
    n = random.getrandbits(bits)
    n |= (1 << (bits - 1)) | 1  # Set MSB and LSB
    if is_prime(n):
      return n


def gcd(a: int, b: int) -> int:
  """Calculate the greatest common divisor using Euclidean algorithm."""
  while b:
    a, b = b, a % b
  return a


def mod_inverse(a: int, m: int) -> int:
  """Calculate modular multiplicative inverse using extended Euclidean algorithm."""

  def extended_gcd(a: int, b: int):
    if a == 0:
      return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

  _, x, _ = extended_gcd(a % m, m)
  return (x % m + m) % m


def generate_keypair(bits: int = 2048) -> tuple:
  """
  Generate an RSA key pair.

  Args:
      bits: Key size in bits (must be at least 512)

  Returns:
      Tuple of ((e, n), (d, n)) where:
      - (e, n) is the public key
      - (d, n) is the private key
  """
  if bits < 512:
    msg = "Key size must be at least 512 bits for security"
    raise ValueError(msg)

  # Generate two distinct primes p and q
  p = generate_prime(bits // 2)
  q = generate_prime(bits // 2)
  while p == q:
    q = generate_prime(bits // 2)

  n = p * q
  phi = (p - 1) * (q - 1)

  # Choose e such that 1 < e < phi and gcd(e, phi) = 1
  e = 65537  # Common choice for e
  if gcd(e, phi) != 1:
    # Find another e if 65537 doesn't work
    e = 3
    while gcd(e, phi) != 1:
      e += 2

  # Calculate d: e * d ≡ 1 (mod phi)
  d = mod_inverse(e, phi)

  return (e, n), (d, n)


def bytes_to_int(data: bytes) -> int:
  """Convert bytes to integer (big-endian)."""
  return int.from_bytes(data, byteorder="big")


def int_to_bytes(value: int, length: int | None = None) -> bytes:
  """Convert integer to bytes (big-endian)."""
  if length is None:
    length = (value.bit_length() + 7) // 8
  return value.to_bytes(length, byteorder="big")


def encrypt(message: bytes, public_key: tuple) -> bytes:
  """
  Encrypt a message using RSA public key.

  Args:
      message: The message to encrypt (must be smaller than key modulus)
      public_key: Tuple of (e, n)

  Returns:
      Encrypted ciphertext as bytes
  """
  e, n = public_key

  # Convert message to integer
  m = bytes_to_int(message)

  if m >= n:
    msg = "Message is too long for the key size"
    raise ValueError(msg)

  # Encrypt: c = m^e mod n
  c = pow(m, e, n)

  # Convert back to bytes
  return int_to_bytes(c)


def decrypt(ciphertext: bytes, private_key: tuple) -> bytes:
  """
  Decrypt ciphertext using RSA private key.

  Args:
      ciphertext: The encrypted data
      private_key: Tuple of (d, n)

  Returns:
      Decrypted message as bytes
  """
  d, n = private_key

  # Convert ciphertext to integer
  c = bytes_to_int(ciphertext)

  # Decrypt: m = c^d mod n
  m = pow(c, d, n)

  # Convert back to bytes
  return int_to_bytes(m)


def sign(message: bytes, private_key: tuple) -> bytes:
  """
  Sign a message using RSA private key.

  Args:
      message: The message to sign
      private_key: Tuple of (d, n)

  Returns:
      Signature as bytes
  """
  d, n = private_key

  # Convert message to integer
  m = bytes_to_int(message)

  if m >= n:
    msg = "Message is too long for the key size"
    raise ValueError(msg)

  # Sign: s = m^d mod n
  s = pow(m, d, n)

  return int_to_bytes(s)


def verify(signature: bytes, message: bytes, public_key: tuple) -> bool:
  """
  Verify a signature using RSA public key.

  Args:
      signature: The signature to verify
      message: The original message
      public_key: Tuple of (e, n)

  Returns:
      True if signature is valid, False otherwise
  """
  e, n = public_key

  try:
    # Convert signature to integer
    s = bytes_to_int(signature)

    # Verify: m' = s^e mod n
    m_prime = pow(s, e, n)

    # Compare with original message
    m = bytes_to_int(message)
  except Exception:
    return False
  else:
    return m_prime == m
