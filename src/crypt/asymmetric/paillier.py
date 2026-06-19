"""Paillier partially homomorphic encryption — pure Python implementation (educational).

Properties:
  - Semantic security under the Decisional Composite Residuosity Assumption
  - Additive homomorphism: D(E(a) * E(b) mod n^2) = a + b mod n

WARNING: Educational only; use a vetted library in production.
"""

import math
import secrets


def _miller_rabin(n: int, k: int = 20) -> bool:
  if n < 2:
    return False
  if n in (2, 3):
    return True
  if n % 2 == 0:
    return False
  r, d = 0, n - 1
  while d % 2 == 0:
    r += 1
    d //= 2
  for _ in range(k):
    a = secrets.randbelow(n - 3) + 2
    x = pow(a, d, n)
    if x in (1, n - 1):
      continue
    for _ in range(r - 1):
      x = pow(x, 2, n)
      if x == n - 1:
        break
    else:
      return False
  return True


def _generate_prime(bits: int) -> int:
  while True:
    p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
    if _miller_rabin(p):
      return p


def _paillier_l(u: int, n: int) -> int:
  """L(u) = (u - 1) / n."""
  return (u - 1) // n


def generate_keypair(bits: int = 512) -> tuple:
  """Generate a Paillier keypair.

  Args:
      bits: bit-length of each prime (n will be 2*bits)

  Returns:
      public_key : (n, g)
      private_key: (lambda_, mu)
  """
  while True:
    p = _generate_prime(bits)
    q = _generate_prime(bits)
    if p == q:
      continue
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    g = n + 1  # common simplification: g = n+1
    n2 = n * n
    mu = pow(_paillier_l(pow(g, lam, n2), n), -1, n)
    return (n, g), (lam, mu)


def encrypt(public_key: tuple, plaintext: int) -> int:
  """Encrypt integer 0 <= m < n."""
  n, g = public_key
  if not (0 <= plaintext < n):
    msg = "Plaintext must satisfy 0 <= m < n"
    raise ValueError(msg)
  n2 = n * n
  while True:
    r = secrets.randbelow(n)
    if math.gcd(r, n) == 1:
      break
  return (pow(g, plaintext, n2) * pow(r, n, n2)) % n2


def decrypt(public_key: tuple, private_key: tuple, ciphertext: int) -> int:
  """Decrypt ciphertext back to plaintext integer."""
  n, _g = public_key
  lam, mu = private_key
  n2 = n * n
  return (_paillier_l(pow(ciphertext, lam, n2), n) * mu) % n


def add_encrypted(public_key: tuple, c1: int, c2: int) -> int:
  """Homomorphic addition: D(result) = D(c1) + D(c2) mod n."""
  n, _ = public_key
  return (c1 * c2) % (n * n)


def add_constant(public_key: tuple, ciphertext: int, k: int) -> int:
  """Add plaintext constant k to an encrypted value."""
  n, g = public_key
  return (ciphertext * pow(g, k, n * n)) % (n * n)
