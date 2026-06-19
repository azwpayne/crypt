"""ElGamal asymmetric encryption — pure Python implementation (educational).

Security relies on the discrete logarithm problem.
WARNING: This is for educational purposes only; use a vetted library in production.
"""

import secrets

# Well-known 1024-bit safe prime (RFC 5114 §2.1 group)
_P = int(
  "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
  "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
  "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
  "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
  "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
  "DF1FB2BC2E4A4371",
  16,
)
_G = 2  # generator


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


def generate_keypair(p: int = _P, g: int = _G) -> tuple:
  """Generate ElGamal keypair.

  Returns:
      public_key : (p, g, h)  where h = g^x mod p
      private_key: x
  """
  x = secrets.randbelow(p - 2) + 2  # private key: 2 <= x <= p-2
  h = pow(g, x, p)
  return (p, g, h), x


def encrypt(public_key: tuple, plaintext: int) -> tuple:
  """Encrypt an integer 0 < m < p.

  Returns ciphertext pair (c1, c2).
  """
  p, g, h = public_key
  if not (0 < plaintext < p):
    msg = "Plaintext must satisfy 0 < m < p"
    raise ValueError(msg)
  y = secrets.randbelow(p - 2) + 2  # ephemeral key
  c1 = pow(g, y, p)
  c2 = (plaintext * pow(h, y, p)) % p
  return c1, c2


def decrypt(public_key: tuple, private_key: int, ciphertext: tuple) -> int:
  """Decrypt ciphertext (c1, c2) back to plaintext integer."""
  p, _g, _h = public_key
  c1, c2 = ciphertext
  s = pow(c1, private_key, p)
  s_inv = pow(s, -1, p)
  return (c2 * s_inv) % p


def encrypt_bytes(public_key: tuple, data: bytes) -> list:
  """Encrypt bytes by encoding each byte as an integer."""
  return [encrypt(public_key, b + 1) for b in data]  # +1 to avoid m=0


def decrypt_bytes(public_key: tuple, private_key: int, ciphertext: list) -> bytes:
  """Decrypt a list of ciphertext pairs back to bytes."""
  return bytes(decrypt(public_key, private_key, ct) - 1 for ct in ciphertext)
