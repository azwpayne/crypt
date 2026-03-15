# DSA (Digital Signature Algorithm)
import random
import hashlib

def generate_parameters(key_size=2048):
    # Simplified parameter generation
    q = 2**256 - 2**224 + 2**192 + 2**96 - 1  # NIST P-256 prime
    p = q * 4 + 1  # Simplified
    g = 2
    return p, q, g

def generate_keypair(p, q, g):
    x = random.randrange(1, q)
    y = pow(g, x, p)
    return x, y  # private, public

def sign(message, p, q, g, x):
    if isinstance(message, str): message = message.encode()
    h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % q
    k = random.randrange(1, q)
    r = pow(g, k, p) % q
    s = (pow(k, -1, q) * (h + x * r)) % q
    return (r, s)

def verify(message, signature, p, q, g, y):
    if isinstance(message, str): message = message.encode()
    r, s = signature
    if not (0 < r < q and 0 < s < q): return False
    h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % q
    w = pow(s, -1, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r
