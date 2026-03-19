"""Pure Python implementation of ECDH key exchange with NIST curves.

Supports NIST curves P-256, P-384, and P-521 for Elliptic Curve Diffie-Hellman.
These curves are also known as secp256r1, secp384r1, and secp521r1.

This implementation is for educational purposes only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class CurveParams:
  """Parameters for an elliptic curve."""

  name: str
  p: int  # Prime modulus
  a: int  # Curve coefficient a
  b: int  # Curve coefficient b
  n: int  # Order of base point
  h: int  # Cofactor
  Gx: int  # Base point x-coordinate
  Gy: int  # Base point y-coordinate


# NIST P-256 (secp256r1)
P256 = CurveParams(
  name="P-256",
  p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
  a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
  b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
  n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
  h=1,
  Gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
  Gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

# NIST P-384 (secp384r1)
P384 = CurveParams(
  name="P-384",
  p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
  a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
  b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
  n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
  h=1,
  Gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
  Gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
)

# NIST P-521 (secp521r1)
P521 = CurveParams(
  name="P-521",
  p=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
  a=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
  b=0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
  n=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
  h=1,
  Gx=0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
  Gy=0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
)

# Curve lookup
CURVES: dict[str, CurveParams] = {
  "P-256": P256,
  "P-384": P384,
  "P-521": P521,
  "secp256r1": P256,
  "secp384r1": P384,
  "secp521r1": P521,
}


class Point:
  """Point on an elliptic curve."""

  def __init__(
    self,
    x: int,
    y: int,
    curve: CurveParams,
    *,
    infinity: bool = False,
  ) -> None:
    self.x = 0 if infinity else x % curve.p
    self.y = 0 if infinity else y % curve.p
    self.curve = curve
    self.infinity = infinity

  def __eq__(self, other: object) -> bool:
    if not isinstance(other, Point):
      return NotImplemented
    return (
      self.x == other.x
      and self.y == other.y
      and self.curve.name == other.curve.name
      and self.infinity == other.infinity
    )

  __hash__ = None

  def is_valid(self) -> bool:
    """Check if point is on the curve."""
    if self.infinity:
      return True
    p = self.curve.p
    lhs = (self.y * self.y) % p
    rhs = (self.x * self.x * self.x + self.curve.a * self.x + self.curve.b) % p
    return lhs == rhs


INFINITY = None  # Placeholder, will be set per curve


def _mod_inv(a: int, m: int) -> int:
  """Compute modular inverse using extended Euclidean algorithm."""
  return pow(a, -1, m)


def point_add(pt1: Point, pt2: Point) -> Point:
  """Add two points on the same curve."""
  if pt1.infinity:
    return pt2
  if pt2.infinity:
    return pt1
  if pt1.x == pt2.x and (pt1.y != pt2.y or pt1.y == 0):
    return Point(0, 0, pt1.curve, infinity=True)

  curve = pt1.curve
  p = curve.p

  if pt1 == pt2:
    # Point doubling
    m = ((3 * pt1.x * pt1.x + curve.a) * _mod_inv(2 * pt1.y, p)) % p
  else:
    # Point addition
    m = ((pt2.y - pt1.y) * _mod_inv(pt2.x - pt1.x, p)) % p

  x3 = (m * m - pt1.x - pt2.x) % p
  y3 = (m * (pt1.x - x3) - pt1.y) % p

  return Point(x3, y3, curve)


def scalar_mult(k: int, point: Point) -> Point:
  """Multiply point by scalar using double-and-add."""
  result = Point(0, 0, point.curve, infinity=True)
  addend = point

  while k > 0:
    if k & 1:
      result = point_add(result, addend)
    addend = point_add(addend, addend)
    k >>= 1

  return result


def generate_keypair(curve_name: str = "P-256") -> tuple[int, Point]:
  """Generate ECDH keypair for specified curve.

  Args:
      curve_name: One of "P-256", "P-384", "P-521" or aliases

  Returns:
      Tuple of (private_key, public_key)

  Raises:
      ValueError: If curve name is invalid
  """
  if curve_name not in CURVES:
    msg = f"Unknown curve: {curve_name}. Use P-256, P-384, or P-521"
    raise ValueError(msg)

  curve = CURVES[curve_name]

  # Generate random private key
  private_key = (
    int.from_bytes(os.urandom((curve.n.bit_length() + 7) // 8), "big") % curve.n
  )
  if private_key == 0:
    private_key = 1

  # Compute public key
  base_point = Point(curve.Gx, curve.Gy, curve)
  public_key = scalar_mult(private_key, base_point)

  return private_key, public_key


def compute_shared_secret(
  private_key: int,
  public_key: Point,
) -> bytes:
  """Compute ECDH shared secret.

  Args:
      private_key: Our private key
      public_key: Peer's public key (Point)

  Returns:
      Shared secret as bytes (x-coordinate of result)
  """
  shared_point = scalar_mult(private_key, public_key)

  if shared_point.infinity:
    msg = "Shared point is at infinity"
    raise ValueError(msg)

  # Return x-coordinate as bytes
  curve = public_key.curve
  return shared_point.x.to_bytes((curve.p.bit_length() + 7) // 8, "big")
