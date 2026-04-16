"""Elliptic Curve Cryptography (secp256k1).

This implementation is for educational purposes only.
"""

from __future__ import annotations

import hashlib
import secrets

# secp256k1 curve parameters
P = 2**256 - 2**32 - 977
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class Point:
  """Point on the secp256k1 elliptic curve."""

  def __init__(self, x: int, y: int, *, infinity: bool = False) -> None:
    self.x = x
    self.y = y
    self.infinity = infinity

  def __eq__(self, other: object) -> bool:
    if not isinstance(other, Point):
      return NotImplemented
    return self.x == other.x and self.y == other.y and self.infinity == other.infinity

  def __hash__(self) -> int:
    msg = "unhashable type"
    raise TypeError(msg)


INFINITY = Point(0, 0, infinity=True)


def point_add(p1: Point, p2: Point) -> Point:
  """Add two points on the secp256k1 curve."""
  if p1.infinity:
    return p2
  if p2.infinity:
    return p1
  if p1.x == p2.x and p1.y != p2.y:
    return INFINITY
  if p1 == p2:
    m = (3 * p1.x * p1.x + A) * pow(2 * p1.y, -1, P) % P
  else:
    m = (p2.y - p1.y) * pow(p2.x - p1.x, -1, P) % P
  x3 = (m * m - p1.x - p2.x) % P
  y3 = (m * (p1.x - x3) - p1.y) % P
  return Point(x3, y3)


def scalar_mult(k: int, point: Point) -> Point:
  """Multiply a point by a scalar using double-and-add."""
  result = INFINITY
  addend = point
  while k:
    if k & 1:
      result = point_add(result, addend)
    addend = point_add(addend, addend)
    k >>= 1
  return result


def generate_keypair() -> tuple[int, Point]:
  """Generate a random secp256k1 keypair."""
  private_key = secrets.randbelow(N - 1) + 1
  public_key = scalar_mult(private_key, Point(Gx, Gy))
  return private_key, public_key


def ecdh_shared_secret(private_key: int, public_key: Point) -> bytes:
  """Compute the ECDH shared secret."""
  shared_point = scalar_mult(private_key, public_key)
  return shared_point.x.to_bytes(32, "big")


def ecdsa_sign(message: bytes | str, private_key: int) -> tuple[int, int]:
  """Sign a message using ECDSA on secp256k1."""
  if isinstance(message, str):
    message = message.encode()
  z = int.from_bytes(hashlib.sha256(message).digest(), "big")
  k = secrets.randbelow(N - 1) + 1
  r_point = scalar_mult(k, Point(Gx, Gy))
  r = r_point.x % N
  s = (pow(k, -1, N) * (z + r * private_key)) % N
  return r, s


def ecdsa_verify(
  message: bytes | str, signature: tuple[int, int], public_key: Point
) -> bool:
  """Verify an ECDSA signature on secp256k1."""
  if isinstance(message, str):
    message = message.encode()
  r, s = signature
  if not (1 <= r < N and 1 <= s < N):
    return False
  z = int.from_bytes(hashlib.sha256(message).digest(), "big")
  w = pow(s, -1, N)
  u1 = (z * w) % N
  u2 = (r * w) % N
  pt1 = scalar_mult(u1, Point(Gx, Gy))
  pt2 = scalar_mult(u2, public_key)
  r_point = point_add(pt1, pt2)
  return r_point.x % N == r
