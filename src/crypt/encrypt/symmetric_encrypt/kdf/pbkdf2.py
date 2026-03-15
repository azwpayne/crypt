# @author  : azwpayne(https://github.com/azwpayne)
# @name    : pbkdf2.py
# @time    : 2026/03/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : PBKDF2 Key Derivation Function (RFC 2898/PKCS #5 v2.0)
"""
PBKDF2 applies a pseudorandom function (HMAC) to the input password
along with a salt value and repeats the process many times to produce
a derived key.

This increases the cost of exhaustive searches and makes dictionary
attacks much more expensive.

Reference: RFC 2898 - PKCS #5: Password-Based Cryptography Specification
"""

import hmac
import hashlib
import struct
from typing import Callable, Union


def _hmac_sha1(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA1 wrapper."""
    return hmac.new(key, msg, hashlib.sha1).digest()


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256 wrapper."""
    return hmac.new(key, msg, hashlib.sha256).digest()


def _hmac_sha512(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA512 wrapper."""
    return hmac.new(key, msg, hashlib.sha512).digest()


def _get_prf(hash_name: str) -> Callable[[bytes, bytes], bytes]:
    """Get the pseudorandom function (HMAC) for the given hash name."""
    hash_name = hash_name.lower().replace("-", "")
    prf_map = {
        "sha1": _hmac_sha1,
        "sha256": _hmac_sha256,
        "sha512": _hmac_sha512,
    }
    if hash_name not in prf_map:
        raise ValueError(f"Unsupported hash function: {hash_name}")
    return prf_map[hash_name]


def _get_hash_digest_size(hash_name: str) -> int:
    """Get the digest size for the given hash name."""
    hash_name = hash_name.lower().replace("-", "")
    size_map = {
        "sha1": 20,
        "sha256": 32,
        "sha512": 64,
    }
    if hash_name not in size_map:
        raise ValueError(f"Unsupported hash function: {hash_name}")
    return size_map[hash_name]


def pbkdf2(
    password: Union[str, bytes],
    salt: Union[str, bytes],
    iterations: int,
    dklen: int = None,
    hash_name: str = "sha256",
) -> bytes:
    """
    PBKDF2 key derivation function (RFC 2898).

    Derives a key from password using HMAC as the pseudorandom function.

    Args:
        password: The password to derive key from
        salt: A random salt (should be unique per password)
        iterations: Number of iterations (higher = more secure but slower)
        dklen: Desired length of derived key in bytes (default: hash digest size)
        hash_name: Hash function to use ('sha1', 'sha256', 'sha512')

    Returns:
        Derived key as bytes

    Raises:
        ValueError: If iterations < 1 or dklen is too large

    Example:
        >>> dk = pbkdf2(b'password', b'salt', 100000, 32)
        >>> len(dk)
        32
    """
    # Convert inputs to bytes
    if isinstance(password, str):
        password = password.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("utf-8")

    # Validate iterations
    if iterations < 1:
        raise ValueError("iterations must be at least 1")

    # Get PRF and its output size
    prf = _get_prf(hash_name)
    hlen = _get_hash_digest_size(hash_name)

    # Determine dklen
    if dklen is None:
        dklen = hlen

    # Maximum derived key length (2^32 - 1) * hLen (RFC 2898)
    max_dklen = (2**32 - 1) * hlen
    if dklen > max_dklen:
        raise ValueError(f"dklen too large, max is {max_dklen}")

    # Number of blocks needed
    l = (dklen + hlen - 1) // hlen
    r = dklen - (l - 1) * hlen

    def _f(i: int) -> bytes:
        """
        Compute F(P, S, c, i) = U_1 xor U_2 xor ... xor U_c
        where U_1 = PRF(P, S || INT_32_BE(i))
        and U_j = PRF(P, U_{j-1})
        """
        # U_1 = PRF(P, S || INT_32_BE(i))
        u = prf(password, salt + struct.pack(">I", i))
        result = bytearray(u)

        # U_2 through U_c
        for _ in range(1, iterations):
            u = prf(password, u)
            # XOR into result
            for j in range(len(result)):
                result[j] ^= u[j]

        return bytes(result)

    # Generate each block
    derived_key = bytearray()
    for i in range(1, l + 1):
        block = _f(i)
        # Last block may be truncated
        if i == l and r != 0:
            derived_key.extend(block[:r])
        else:
            derived_key.extend(block)

    return bytes(derived_key)


# Convenience aliases for common configurations


def pbkdf2_sha1(password: Union[str, bytes], salt: Union[str, bytes], iterations: int, dklen: int = None) -> bytes:
    """PBKDF2 with SHA1."""
    return pbkdf2(password, salt, iterations, dklen, hash_name="sha1")


def pbkdf2_sha256(password: Union[str, bytes], salt: Union[str, bytes], iterations: int, dklen: int = None) -> bytes:
    """PBKDF2 with SHA256."""
    return pbkdf2(password, salt, iterations, dklen, hash_name="sha256")


def pbkdf2_sha512(password: Union[str, bytes], salt: Union[str, bytes], iterations: int, dklen: int = None) -> bytes:
    """PBKDF2 with SHA512."""
    return pbkdf2(password, salt, iterations, dklen, hash_name="sha512")
