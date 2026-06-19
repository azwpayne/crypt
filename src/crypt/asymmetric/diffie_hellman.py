"""Diffie-Hellman key exchange — educational textbook implementation.

.. warning::
    **Educational only — not for production key agreement.**

    This is bare textbook DH: unauthenticated, with no key confirmation and no
    parameter validation beyond RFC 3526. It is vulnerable to man-in-the-middle
    attacks. Real deployments need authenticated DH (e.g. signed/verified
    ephemeral keys) and must feed the shared secret through a KDF (e.g. HKDF).

Security note on randomness:
    The private exponent is generated with :mod:`secrets` (CSPRNG), as required
    for a DH secret. Using the non-cryptographic :mod:`random` module here would
    let an attacker reconstruct the PRNG state from observed output and recover
    the private key — a critical vulnerability.
"""

import secrets

# Standard DH parameters (RFC 3526 - 2048-bit MODP Group)
P = int(
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
  16,
)
G = 2


def generate_private_key(bits: int = 2048) -> int:
  """Generate a DH private exponent using a CSPRNG.

  Args:
      bits: Bit length of the private exponent.

  Returns:
      A cryptographically-random integer in ``[0, 2**bits)``.

  .. warning:: Uses :func:`secrets.randbits` (CSPRNG). The :mod:`random` module
      MUST NOT be used here — a DH private key must be unpredictable.
  """
  return secrets.randbits(bits)


def generate_public_key(private_key: int, p: int = P, g: int = G) -> int:
  """Compute the DH public value ``g**private_key mod p``."""
  return pow(g, private_key, p)


def compute_shared_secret(private_key: int, public_key: int, p: int = P) -> int:
  """Compute the shared secret ``public_key**private_key mod p``.

  .. warning:: The raw shared secret is NOT a key — feed it through a KDF
      (e.g. HKDF) before use in any symmetric primitive.
  """
  return pow(public_key, private_key, p)
