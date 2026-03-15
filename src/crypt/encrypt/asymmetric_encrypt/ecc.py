# Elliptic Curve Cryptography
import random
import hashlib

# secp256k1 curve parameters
P = 2**256 - 2**32 - 977
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class Point:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.infinity == other.infinity

INFINITY = Point(0, 0, True)

def point_add(P1, P2):
    if P1.infinity: return P2
    if P2.infinity: return P1
    if P1.x == P2.x and P1.y != P2.y: return INFINITY
    if P1 == P2:
        m = (3 * P1.x * P1.x + A) * pow(2 * P1.y, -1, P) % P
    else:
        m = (P2.y - P1.y) * pow(P2.x - P1.x, -1, P) % P
    x3 = (m * m - P1.x - P2.x) % P
    y3 = (m * (P1.x - x3) - P1.y) % P
    return Point(x3, y3)

def scalar_mult(k, point):
    result = INFINITY
    addend = point
    while k:
        if k & 1: result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def generate_keypair():
    private_key = random.randrange(1, N)
    public_key = scalar_mult(private_key, Point(Gx, Gy))
    return private_key, public_key

def ecdh_shared_secret(private_key, public_key):
    shared_point = scalar_mult(private_key, public_key)
    return shared_point.x.to_bytes(32, 'big')

def ecdsa_sign(message, private_key):
    if isinstance(message, str): message = message.encode()
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    k = random.randrange(1, N)
    R = scalar_mult(k, Point(Gx, Gy))
    r = R.x % N
    s = (pow(k, -1, N) * (z + r * private_key)) % N
    return (r, s)

def ecdsa_verify(message, signature, public_key):
    if isinstance(message, str): message = message.encode()
    r, s = signature
    if not (1 <= r < N and 1 <= s < N): return False
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    w = pow(s, -1, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    P1 = scalar_mult(u1, Point(Gx, Gy))
    P2 = scalar_mult(u2, public_key)
    R = point_add(P1, P2)
    return R.x % N == r
