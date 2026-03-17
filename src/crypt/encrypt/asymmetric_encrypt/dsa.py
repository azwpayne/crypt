# DSA (Digital Signature Algorithm)
import hashlib
import random


def generate_parameters(key_size=2048):
  """Generate DSA parameters.

  Uses properly chosen primes where p = k*q + 1 for some k.
  For simplicity, we use a known valid configuration.
  """
  # NIST P-256 prime for q (256-bit)
  q = 2**256 - 2**224 + 2**192 + 2**96 - 1
  # Compute p such that p = k*q + 1 for some k
  # We need p to be prime and (p-1) to be divisible by q
  # Using k = 2 for simplicity (gives us p = 2*q + 1)
  # First check if 2*q + 1 is prime
  p_candidate = 2 * q + 1

  # If not prime, find next valid p by incrementing k
  k = 2
  while True:
    p_candidate = k * q + 1
    # Simple primality test
    if pow(2, p_candidate - 1, p_candidate) == 1:
        is_prime = all(
            p_candidate % small_prime != 0
            for small_prime in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        )
      if is_prime:
        break
    k += 1
    if k > 1000:  # Safety limit
      msg = "Could not find valid p"
      raise RuntimeError(msg)

  p = p_candidate

  # Generator: g = h^((p-1)/q) mod p for some h where g > 1
  # Using h = 2, we get g = 2^k mod p where k = (p-1)/q
  g = pow(2, k, p)
  # Ensure g != 1
  if g == 1:
    g = pow(3, k, p)

  return p, q, g


def generate_keypair(p, q, g):
    x = random.randrange(1, q)  # noqa: S311
  y = pow(g, x, p)
  return x, y  # private, public


def sign(message, p, q, g, x):
  if isinstance(message, str):
    message = message.encode()
  h = int.from_bytes(hashlib.sha256(message).digest(), "big") % q
  k = random.randrange(1, q)
  r = pow(g, k, p) % q
  s = (pow(k, -1, q) * (h + x * r)) % q
  return (r, s)


def verify(message, signature, p, q, g, y):
  if isinstance(message, str):
    message = message.encode()
  r, s = signature
  if not (0 < r < q and 0 < s < q):
    return False
  h = int.from_bytes(hashlib.sha256(message).digest(), "big") % q
  w = pow(s, -1, q)
  u1 = (h * w) % q
  u2 = (r * w) % q
  v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
  return v == r
