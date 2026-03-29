"""
NTRU post-quantum encryption implementation.

This module provides a simplified educational implementation of the NTRU
lattice-based public key cryptosystem, which is resistant to attacks by
both classical and quantum computers.

NTRU operates on polynomials in the truncated polynomial ring
Z[X]/(X^N - 1) with coefficients reduced modulo q.

Parameters (NTRU-251 educational variant):
  N  = 251  — polynomial degree (prime, coprime to q)
  p  = 3    — small modulus for message space
  q  = 2053  — large modulus for public key (prime, enables EGCD)
  df = 72   — number of +1/-1 coefficients in private key f
  dg = 72   — number of +1/-1 coefficients in private key g
  dr = 60   — number of +1/-1 coefficients in blinding polynomial r

Note: q must be prime so that Z_q is a field, enabling polynomial
inverse computation via the extended Euclidean algorithm.

Reference:
  Hoffstein, Pipher, Silverman — "NTRU: A Ring-Based Public Key
  Cryptosystem" (ANTS III, 1998).
"""

import secrets

# ── Polynomial helpers ──────────────────────────────────────────────────


def _poly_add(a: list[int], b: list[int], mod: int, n: int) -> list[int]:
  """Add two polynomials in Z[X]/(X^N - 1), coefficients reduced mod *mod*."""
  return [(a[i] + b[i]) % mod for i in range(n)]


def _poly_mul(a: list[int], b: list[int], mod: int, n: int) -> list[int]:
  """Multiply two polynomials in Z[X]/(X^N - 1), coefficients reduced mod *mod*."""
  result = [0] * n
  for i in range(len(a)):
    if a[i] == 0:
      continue
    for j in range(len(b)):
      if b[j] == 0:
        continue
      result[(i + j) % n] = (result[(i + j) % n] + a[i] * b[j]) % mod
  return result


def _poly_mul_plain(a: list[int], b: list[int], p: int) -> list[int]:
  """Multiply two polynomials in Z_p[X] (no quotient-ring wrapping)."""
  if _poly_is_zero(a) or _poly_is_zero(b):
    return [0]
  result = [0] * (len(a) + len(b) - 1)
  for i in range(len(a)):
    for j in range(len(b)):
      result[i + j] = (result[i + j] + a[i] * b[j]) % p
  return _poly_trim(result)


def _poly_scalar_mul(poly: list[int], scalar: int, mod: int, _n: int) -> list[int]:
  """Multiply a polynomial by a scalar, coefficients reduced mod *mod*."""
  return [(c * scalar) % mod for c in poly]


def _center_lift(poly: list[int], q: int) -> list[int]:
  """Center-lift coefficients from {0, …, q-1} to {-(q//2), …, q//2}."""
  half = q // 2
  return [c - q if c > half else c for c in poly]


def _mod_p_reduce(poly: list[int], p: int) -> list[int]:
  """Reduce coefficients to balanced representation in {-(p-1)/2, …, (p-1)/2}."""
  result = [c % p for c in poly]
  half = p // 2
  return [c - p if c > half else c for c in result]


def _poly_trim(poly: list[int]) -> list[int]:
  """Remove trailing zero coefficients."""
  result = list(poly)
  while len(result) > 1 and result[-1] == 0:
    result.pop()
  return result


def _poly_is_zero(poly: list[int]) -> bool:
  """Check whether *poly* is the zero polynomial."""
  return all(c == 0 for c in poly)


def _poly_degree(poly: list[int]) -> int:
  """Return the degree of *poly*, or -1 for the zero polynomial."""
  trimmed = _poly_trim(poly)
  if len(trimmed) == 1 and trimmed[0] == 0:
    return -1
  return len(trimmed) - 1


def _poly_divmod(
  a: list[int],
  b: list[int],
  mod: int,
) -> tuple[list[int], list[int]]:
  """Polynomial long division in Z_mod[X].  Returns (quotient, remainder)."""
  a = [c % mod for c in _poly_trim(a)]
  b = [c % mod for c in _poly_trim(b)]

  if _poly_is_zero(b):
    msg = "Division by zero polynomial"
    raise ZeroDivisionError(msg)

  deg_b = _poly_degree(b)
  lead_b = b[-1]
  lead_inv = pow(lead_b, -1, mod)

  remainder = list(a)
  deg_r = _poly_degree(remainder)
  quotient = [0] * max(1, deg_r - deg_b + 1) if deg_r >= deg_b else [0]

  while deg_r >= deg_b and not _poly_is_zero(remainder):
    coeff = (remainder[deg_r] * lead_inv) % mod
    shift = deg_r - deg_b
    quotient[shift] = coeff
    for i in range(len(b)):
      remainder[shift + i] = (remainder[shift + i] - coeff * b[i]) % mod
    # Recompute degree: leading term should now be zero
    while deg_r > 0 and remainder[deg_r] == 0:
      deg_r -= 1

  return _poly_trim(quotient), _poly_trim(remainder)


def _poly_egcd(
  a: list[int],
  b: list[int],
  mod: int,
) -> tuple[list[int], list[int], list[int]]:
  """
  Extended Euclidean algorithm for polynomials over Z_mod.

  Returns (g, u, v) such that  u*a + v*b = g  where g = gcd(a, b)
  in Z_mod[X].  The leading coefficient of g is normalised to 1
  (when invertible in Z_mod).
  """
  old_r = [c % mod for c in _poly_trim(a)]
  r = [c % mod for c in _poly_trim(b)]
  old_s = [1]
  s = [0]
  old_t = [0]
  t = [1]

  while not _poly_is_zero(r):
    q_poly, rem = _poly_divmod(old_r, r, mod)
    old_r, r = r, rem
    qs = _poly_mul_plain(q_poly, s, mod)
    new_s = _poly_trim(
      [
        (old_s[i] if i < len(old_s) else 0) - (qs[i] if i < len(qs) else 0)
        for i in range(max(len(old_s), len(qs)))
      ]
    )
    old_s, s = s, [c % mod for c in new_s]
    qt = _poly_mul_plain(q_poly, t, mod)
    new_t = _poly_trim(
      [
        (old_t[i] if i < len(old_t) else 0) - (qt[i] if i < len(qt) else 0)
        for i in range(max(len(old_t), len(qt)))
      ]
    )
    old_t, t = t, [c % mod for c in new_t]

  g = old_r
  u = old_s
  if not _poly_is_zero(g):
    lead_inv = pow(g[-1], -1, mod)
    g = [(c * lead_inv) % mod for c in g]
    u = [(c * lead_inv) % mod for c in u]

  return g, u, old_t


def _poly_mod_inverse(poly: list[int], mod: int, n: int) -> list[int]:
  """
  Compute the multiplicative inverse of *poly* in Z[X]/(X^N - 1, mod).

  Uses the extended Euclidean algorithm to compute gcd(poly, X^N - 1)
  in Z_mod[X].  If the gcd is a non-zero constant, the corresponding
  Bézout coefficient (reduced mod X^N - 1) is the inverse.
  """
  xn1 = [(-1) % mod] + [0] * (n - 1) + [1]
  g, u, _v = _poly_egcd(poly, xn1, mod)

  if _poly_is_zero(g):
    msg = "Polynomial is not invertible (gcd is zero)"
    raise ValueError(msg)

  g_const = g[0] % mod
  if g_const == 0:
    msg = "Polynomial is not invertible in the quotient ring"
    raise ValueError(msg)

  g_inv = pow(g_const, -1, mod)
  inv = _poly_scalar_mul(u, g_inv, mod, n)

  result = [0] * n
  for i, c in enumerate(inv):
    result[i % n] = (result[i % n] + c) % mod

  return result


def _generate_trinary(n: int, num_ones: int, num_neg_ones: int) -> list[int]:
  """
  Generate a trinary polynomial with exactly *num_ones* +1 coefficients,
  *num_neg_ones* -1 coefficients, and the rest 0.

  Uses cryptographically secure randomness via the *secrets* module.
  """
  if num_ones + num_neg_ones > n:
    msg = "Total non-zero coefficients exceed polynomial degree"
    raise ValueError(msg)

  poly = [0] * n
  indices = list(range(n))

  # Fisher-Yates shuffle using secrets for index selection
  for i in range(n - 1, 0, -1):
    j = secrets.randbelow(i + 1)
    indices[i], indices[j] = indices[j], indices[i]

  for i in range(num_ones):
    poly[indices[i]] = 1
  for i in range(num_ones, num_ones + num_neg_ones):
    poly[indices[i]] = -1

  return poly


def _poly_to_bytes(poly: list[int], p: int) -> bytes:
  """Decode a trinary polynomial back to bytes via base-3 integer."""
  digits = [(c + p) % p for c in poly]
  value = 0
  for d in reversed(digits):
    value = value * 3 + d
  byte_len = (value.bit_length() + 7) // 8 if value > 0 else 1
  return value.to_bytes(byte_len, "big")


def _bytes_to_poly(data: bytes, n: int) -> list[int]:
  """Encode bytes as a trinary polynomial via base-3 representation."""
  value = int.from_bytes(data, "big") if data else 0
  poly = []
  for _ in range(n):
    poly.append(value % 3)
    value //= 3
  return [c - 3 if c == 2 else c for c in poly]


def _pack_coeffs(coeffs: list[int], bits_per: int, n: int) -> bytes:
  """Pack *n* integer coefficients into bytes, *bits_per* bits each."""
  out = bytearray()
  buf = 0
  buf_bits = 0
  for c in coeffs[:n]:
    buf = (buf << bits_per) | (c & ((1 << bits_per) - 1))
    buf_bits += bits_per
    while buf_bits >= 8:
      buf_bits -= 8
      out.append((buf >> buf_bits) & 0xFF)
  if buf_bits > 0:
    out.append((buf << (8 - buf_bits)) & 0xFF)
  return bytes(out)


def _unpack_coeffs(data: bytes, bits_per: int, n: int) -> list[int]:
  """Unpack bytes into *n* integer coefficients, *bits_per* bits each."""
  mask = (1 << bits_per) - 1
  buf = 0
  buf_bits = 0
  byte_idx = 0
  coeffs = []
  while len(coeffs) < n:
    while buf_bits < bits_per:
      if byte_idx >= len(data):
        buf <<= bits_per - buf_bits
        buf_bits = bits_per
        break
      buf = (buf << 8) | data[byte_idx]
      byte_idx += 1
      buf_bits += 8
    buf_bits -= bits_per
    coeffs.append((buf >> buf_bits) & mask)
    buf &= (1 << buf_bits) - 1
  return coeffs


def _int_to_poly(value: int, n: int) -> list[int]:
  """Convert an integer to a polynomial (little-endian base-p=3 digits)."""
  poly = []
  for _ in range(n):
    poly.append(value % 3)
    value //= 3
  # Center-lift: 2 -> -1
  return [c - 3 if c == 2 else c for c in poly]


def _poly_to_int(poly: list[int]) -> int:
  """Convert a polynomial with coefficients in {0, 1, 2} to an integer."""
  # Normalize to {0, 1, 2}
  normalized = [c % 3 for c in poly]
  value = 0
  for i in range(len(normalized) - 1, -1, -1):
    value = value * 3 + normalized[i]
  return value


# ── Public API ──────────────────────────────────────────────────────────


def ntru_generate_keypair(
  n: int = 251,
  p: int = 3,
  q: int = 2053,
  df: int = 72,
  dg: int = 72,
) -> tuple[dict, dict]:
  """
  Generate an NTRU key pair.

  Args:
      n:  Polynomial degree (must be prime and coprime to q).
      p:  Small modulus for message space (typically 3).
      q:  Large modulus for public key (typically 256).
      df: Number of +1 and -1 coefficients in private key polynomial f.
      dg: Number of +1 and -1 coefficients in polynomial g.

  Returns:
      Tuple of (public_key, private_key) where:
      - public_key  = {"h": list[int], "n": int, "p": int, "q": int}
      - private_key = {"f": list[int], "fp": list[int], "n": int,
                        "p": int, "q": int}
      Polynomials are represented as lists of *n* integer coefficients.
  """
  # Generate f: df ones, df negative-ones, rest zeros.
  # Retry until f is invertible mod q and mod p.
  max_attempts = 100
  for _ in range(max_attempts):
    f = _generate_trinary(n, df + 1, df)
    try:
      fq = _poly_mod_inverse(f, q, n)
      fp = _poly_mod_inverse(f, p, n)
      break
    except (ValueError, ZeroDivisionError):
      continue
  else:
    msg = "Failed to generate invertible f after multiple attempts"
    raise RuntimeError(msg)

  # Generate g: dg ones, dg negative-ones, rest zeros.
  g = _generate_trinary(n, dg, dg)

  # Public key: h = p * fq * g  mod q
  h = _poly_scalar_mul(fq, p, q, n)
  h = _poly_mul(h, g, q, n)

  public_key = {"h": h, "n": n, "p": p, "q": q}
  private_key = {"f": f, "fp": fp, "n": n, "p": p, "q": q}
  return public_key, private_key


def ntru_encrypt(plaintext: bytes, public_key: dict) -> bytes:
  """
  Encrypt *plaintext* using an NTRU public key.

  The message is first converted to a polynomial in Z[X]/(X^N - 1) with
  coefficients in {0, 1, -1}, then encrypted as:
      c = r * h + m   (mod q)

  Args:
      plaintext:  The message bytes to encrypt.
      public_key: Dict with keys "h", "n", "p", "q".

  Returns:
      Encrypted ciphertext as bytes.
  """
  n = public_key["n"]
  p = public_key["p"]
  q = public_key["q"]
  h = public_key["h"]

  # Convert plaintext bytes to a trinary polynomial
  m = _bytes_to_poly(plaintext, n)

  # Generate random blinding polynomial r
  dr = (n - 1) // 5
  r = _generate_trinary(n, dr, dr)

  # Encrypt: c = r * h + m  mod q
  rh = _poly_mul(r, h, q, n)
  c = _poly_add(rh, m, q, n)

  # Serialize ciphertext: coefficients are 0..2052, pack as 11-bit values
  return _pack_coeffs(c, 12, n)


def ntru_decrypt(ciphertext: bytes, private_key: dict) -> bytes:
  """
  Decrypt *ciphertext* using an NTRU private key.

  Decryption steps:
      a  = f * c          (mod q)
      a' = center_lift(a)  — coefficients into (-q/2, q/2]
      m  = fp * a'         (mod p)

  Args:
      ciphertext: The encrypted data (one byte per polynomial coefficient).
      private_key: Dict with keys "f", "fp", "n", "p", "q".

  Returns:
      Decrypted message as bytes.
  """
  n = private_key["n"]
  p = private_key["p"]
  q = private_key["q"]
  f = private_key["f"]
  fp = private_key["fp"]

  # Deserialize ciphertext: unpack 11-bit coefficients
  c = _unpack_coeffs(ciphertext, 12, n)

  # Step 1: a = f * c  mod q
  a = _poly_mul(f, c, q, n)

  # Step 2: center-lift a
  a = _center_lift(a, q)

  # Step 3: m = fp * a  mod p
  m = _poly_mul(fp, a, p, n)
  m = _mod_p_reduce(m, p)

  # Convert trinary polynomial back to bytes
  return _poly_to_bytes(m, p)
