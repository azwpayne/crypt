"""Pure Python implementation of Ed25519 signature algorithm.

Ed25519 is an Edwards-curve Digital Signature Algorithm based on RFC 8032.
It uses Curve25519 in Edwards form with the equation:
    -x² + y² = 1 + d*x²*y²
where d = -121665/121666 mod p

This implementation is for educational purposes only.
"""

from __future__ import annotations

import hashlib
import os
from typing import Final

# Curve parameters
P: Final[int] = 2**255 - 19  # Prime field
D: Final[int] = (-121665 * pow(121666, -1, P)) % P  # Curve constant

# Base point B coordinates
BX: Final[int] = (
  15112221349535400772501151409588531511454012693041857206046113283949847762202
)
BY: Final[int] = (
  46316835694926478169428394003475163141307993866256225615783033603165251855960
)

# Order of the base point
L: Final[int] = 2**252 + 27742317777372353535851937790883648493


def _modp_inv(x: int) -> int:
  """Compute modular inverse mod P."""
  return pow(x, P - 2, P)


def _modp_sqrt(x: int) -> int:
  """Compute square root mod P (where P ≡ 5 mod 8)."""
  # For p ≡ 5 (mod 8), sqrt(x) = x^((p+3)/8) or x^((p+3)/8) * 2^((p-1)/4)
  sqrt_candidate = pow(x, (P + 3) // 8, P)
  if (sqrt_candidate * sqrt_candidate) % P == x % P:
    return sqrt_candidate
  return (sqrt_candidate * pow(2, (P - 1) // 4, P)) % P


class Point:
  """Point on Edwards curve."""

  def __init__(self, x: int, y: int) -> None:
    self.x = x % P
    self.y = y % P

  def __eq__(self, other: object) -> bool:
    if not isinstance(other, Point):
      return NotImplemented
    return self.x == other.x and self.y == other.y

  __hash__ = None  # type: ignore[assignment]

  def is_valid(self) -> bool:
    """Check if point is on the curve."""
    x2 = (self.x * self.x) % P
    y2 = (self.y * self.y) % P
    lhs = (-x2 + y2) % P
    rhs = (1 + D * x2 * y2) % P
    return lhs == rhs


# Base point
B = Point(BX, BY)


def point_add(p1: Point, p2: Point) -> Point:
  """Add two points on the Edwards curve."""
  x1, y1 = p1.x, p1.y
  x2, y2 = p2.x, p2.y

  # Edwards addition formula
  x3 = ((x1 * y2 + x2 * y1) * _modp_inv(1 + D * x1 * x2 * y1 * y2)) % P
  y3 = ((y1 * y2 + x1 * x2) * _modp_inv(1 - D * x1 * x2 * y1 * y2)) % P

  return Point(x3, y3)


def scalar_mult(k: int, point: Point) -> Point:
  """Multiply point by scalar using double-and-add."""
  result = Point(0, 1)  # Identity point
  addend = point

  while k > 0:
    if k & 1:
      result = point_add(result, addend)
    addend = point_add(addend, addend)
    k >>= 1

  return result


def encode_point(point: Point) -> bytes:
  """Encode point to 32 bytes (y-coordinate with sign bit)."""
  y = point.y
  # Set sign bit based on x parity
  if point.x & 1:
    y |= 1 << 255
  return y.to_bytes(32, "little")


def decode_point(data: bytes) -> Point | None:
  """Decode point from 32 bytes. Returns None if invalid."""
  if len(data) != 32:
    return None

  y = int.from_bytes(data, "little")
  sign = y >> 255
  y &= (1 << 255) - 1

  if y >= P:
    return None

  # Recover x from curve equation: x² = (y² - 1) / (d*y² + 1)
  y2 = (y * y) % P
  x2 = ((y2 - 1) * _modp_inv(D * y2 + 1)) % P
  x = _modp_sqrt(x2)

  if x is None or (x * x) % P != x2:
    return None

  if x & 1 != sign:
    x = (-x) % P

  point = Point(x, y)
  if not point.is_valid():
    return None

  return point


def _h(message: bytes) -> bytes:
  """Hash function (SHA-512)."""
  return hashlib.sha512(message).digest()


def generate_keypair() -> tuple[bytes, bytes]:
  """Generate Ed25519 keypair.

  Returns:
      Tuple of (private_key, public_key) as 32-byte each
  """
  # Generate random 32-byte private key
  private_key = os.urandom(32)

  # Compute public key
  public_key = generate_public_key(private_key)

  return private_key, public_key


def generate_public_key(private_key: bytes) -> bytes:
  """Generate public key from private key.

  Args:
      private_key: 32-byte private key

  Returns:
      32-byte public key
  """
  if len(private_key) != 32:
    msg = "Private key must be 32 bytes"
    raise ValueError(msg)

  # Hash private key
  h = _h(private_key)

  # Clamp first half of hash
  a = int.from_bytes(h[:32], "little")
  a &= (1 << 254) - 8  # Clear bits 0, 1, 2
  a |= 1 << 254  # Set bit 254

  # Compute public key A = a * B
  a_point = scalar_mult(a, B)

  return encode_point(a_point)


def sign(message: bytes, private_key: bytes) -> bytes:
  """Sign a message with Ed25519.

  Args:
      message: Message to sign
      private_key: 32-byte private key

  Returns:
      64-byte signature
  """
  if len(private_key) != 32:
    msg = "Private key must be 32 bytes"
    raise ValueError(msg)

  # Hash private key
  h = _h(private_key)

  # Clamp first half
  a = int.from_bytes(h[:32], "little")
  a &= (1 << 254) - 8
  a |= 1 << 254

  # Compute public key
  a_point = scalar_mult(a, B)
  public_key = encode_point(a_point)

  # Compute r = H(h[32:64] || message)
  r = int.from_bytes(_h(h[32:64] + message), "little") % L

  # Compute R = r * B
  r_point = scalar_mult(r, B)

  # Compute k = H(R || A || message)
  k = int.from_bytes(_h(encode_point(r_point) + public_key + message), "little") % L

  # Compute s = (r + k * a) mod L
  s = (r + k * a) % L

  # Signature is R || s
  return encode_point(r_point) + s.to_bytes(32, "little")


def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
  """Verify an Ed25519 signature.

  Args:
      signature: 64-byte signature
      message: Original message
      public_key: 32-byte public key

  Returns:
      True if valid, False otherwise
  """
  if len(signature) != 64:
    return False
  if len(public_key) != 32:
    return False

  # Decode R and s
  r_bytes = signature[:32]
  s = int.from_bytes(signature[32:], "little")

  if s >= L:
    return False

  # Decode points
  r_point = decode_point(r_bytes)
  a_point = decode_point(public_key)

  if r_point is None or a_point is None:
    return False

  # Compute k = H(R || A || message)
  k = int.from_bytes(_h(r_bytes + public_key + message), "little") % L

  # Verify: s * B == R + k * A
  lhs = scalar_mult(s, B)
  rhs = point_add(r_point, scalar_mult(k, a_point))

  return lhs == rhs
