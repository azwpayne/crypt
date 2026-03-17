"""DSA (Digital Signature Algorithm) implementation.

This module provides a pure Python implementation of the DSA algorithm
for educational purposes. For production use, please use established
cryptographic libraries like `cryptography`.
"""

from __future__ import annotations

import hashlib
import secrets


def generate_parameters(key_size: int = 2048) -> tuple[int, int, int]:
  """Generate DSA parameters p, q, g.

  Generates DSA domain parameters where:
  - p is a large prime (key_size bits)
  - q is a 256-bit prime divisor of p-1
  - g is a generator of order q

  Args:
      key_size: The desired bit length of p (default 2048).

  Returns:
      A tuple (p, q, g) containing the DSA parameters.

  Raises:
      RuntimeError: If valid parameters cannot be generated.
  """
  # q is a 256-bit prime
  # Use a standard NIST q value for consistency
  q = 2**256 - 2**224 + 2**192 + 2**96 - 1

  # Find p such that p = k*q + 1 for some k
  # and p is prime with the desired bit length
  # Start with k large enough to get the desired bit length for p
  # p = k*q + 1, so k ≈ 2^(key_size - 256)
  k = max(2, 2 ** (key_size - 256))
  max_attempts = 1000
  attempts = 0

  while attempts < max_attempts:
    p_candidate = k * q + 1

    # Check if p is prime using Fermat's test and trial division
    if pow(2, p_candidate - 1, p_candidate) == 1:
      is_prime = all(
        p_candidate % small_prime != 0
        for small_prime in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
      )
      if is_prime:
        break

    k += 1
    attempts += 1
  else:
    msg = f"Could not find valid p after {max_attempts} attempts"
    raise RuntimeError(msg)

  p = p_candidate

  # Generator: g = h^((p-1)/q) mod p for some h where g > 1
  # Using h = 2 initially
  h = 2
  exponent = (p - 1) // q
  g = pow(h, exponent, p)

  # If g == 1, try different h values
  while g == 1 and h < 100:
    h += 1
    g = pow(h, exponent, p)

  if g == 1:
    msg = "Could not find valid generator g"
    raise RuntimeError(msg)

  return p, q, g


def generate_keypair(p: int, q: int, g: int) -> tuple[int, int]:
  """Generate a DSA key pair.

  Args:
      p: The prime modulus.
      q: The prime order.
      g: The generator.

  Returns:
      A tuple (x, y) where x is the private key and y is the public key.
  """
  x = secrets.randbelow(q - 1) + 1  # Private key: 1 <= x < q
  y = pow(g, x, p)  # Public key: y = g^x mod p
  return x, y


def sign(
  message: bytes | str,
  p: int,
  q: int,
  g: int,
  x: int,
) -> tuple[int, int]:
  """Sign a message using DSA.

  Args:
      message: The message to sign (bytes or string).
      p: The prime modulus.
      q: The prime order.
      g: The generator.
      x: The private key.

  Returns:
      A tuple (r, s) representing the signature.
  """
  if isinstance(message, str):
    message = message.encode()

  # Hash the message
  h = int.from_bytes(hashlib.sha256(message).digest(), "big") % q

  # Generate random k
  k = secrets.randbelow(q - 1) + 1

  # Compute r = (g^k mod p) mod q
  r = pow(g, k, p) % q

  # Compute s = k^-1 * (h + x*r) mod q
  k_inv = pow(k, -1, q)
  s = (k_inv * (h + x * r)) % q

  return r, s


def verify(
  message: bytes | str,
  signature: tuple[int, int],
  p: int,
  q: int,
  g: int,
  y: int,
) -> bool:
  """Verify a DSA signature.

  Args:
      message: The message that was signed (bytes or string).
      signature: A tuple (r, s) representing the signature.
      p: The prime modulus.
      q: The prime order.
      g: The generator.
      y: The public key.

  Returns:
      True if the signature is valid, False otherwise.
  """
  if isinstance(message, str):
    message = message.encode()

  r, s = signature

  # Verify r and s are in valid range
  if not (0 < r < q and 0 < s < q):
    return False

  # Hash the message
  h = int.from_bytes(hashlib.sha256(message).digest(), "big") % q

  # Compute w = s^-1 mod q
  w = pow(s, -1, q)

  # Compute u1 = h * w mod q
  u1 = (h * w) % q

  # Compute u2 = r * w mod q
  u2 = (r * w) % q

  # Compute v = ((g^u1 * y^u2) mod p) mod q
  v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

  return v == r
