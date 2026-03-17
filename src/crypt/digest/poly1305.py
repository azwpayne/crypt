# @author  : azwpayne(https://github.com/azwpayne)
# @name    : poly1305.py
# @time    : 2026/03/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Poly1305 Message Authentication Code (RFC 8439)
"""
Poly1305 is a one-time message authenticator designed by D. J. Bernstein.
It is used with ChaCha20 in TLS 1.3 and other protocols.

IMPORTANT: The key must never be reused for different messages.

Reference: RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols
"""


def _clamp_r(r: int) -> int:
  """
  Clamp the r value by clearing certain bits.
  This ensures the multiplier is in a safe range.
  """
  # Clear bits: 3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63
  r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
  return r


def _mul_mod(a: int, b: int) -> int:
  """
  Multiply two numbers modulo 2^130 - 5.
  """
  # Prime for Poly1305: 2^130 - 5
  p = (1 << 130) - 5
  return (a * b) % p


def poly1305_mac(key: bytes | str, message: bytes | str) -> bytes:
  """
  Compute Poly1305 message authentication code.

  Args:
      key: 32-byte key (r || s), where r and s are 16 bytes each.
           r is clamped before use.
      message: Message to authenticate

  Returns:
      16-byte authentication tag

  Raises:
      ValueError: If key is not 32 bytes

  Note:
      The key MUST NOT be reused for different messages.
      Generate a new random key for each message.
  """
  # Convert inputs to bytes
  if isinstance(key, str):
    key = key.encode("utf-8")
  if isinstance(message, str):
    message = message.encode("utf-8")

  # Validate key length
  if len(key) != 32:
    msg = f"Key must be 32 bytes, got {len(key)}"
    raise ValueError(msg)

  # Split key into r and s
  r = int.from_bytes(key[:16], "little")
  s = int.from_bytes(key[16:], "little")

  # Clamp r
  r = _clamp_r(r)

  # Prime for Poly1305
  p = (1 << 130) - 5

  # Accumulator
  acc = 0

  # Process message in 16-byte blocks
  for i in range(0, len(message), 16):
    block = message[i : i + 16]

    # Append 0x01 byte and pad with zeros
    # This creates a 17-byte block where the last byte is 0x01
    n = int.from_bytes(block + b"\x01", "little")

    # Add to accumulator
    acc = (acc + n) % p

    # Multiply by r
    acc = _mul_mod(acc, r)

  # Add s to accumulator (modulo 2^128)
  result = (acc + s) % (1 << 128)

  # Convert to 16-byte little-endian
  return result.to_bytes(16, "little")


def poly1305_verify(key: bytes | str, message: bytes | str, tag: bytes) -> bool:
  """
  Verify a Poly1305 authentication tag.

  Args:
      key: 32-byte key
      message: Message that was authenticated
      tag: 16-byte authentication tag to verify

  Returns:
      True if the tag is valid, False otherwise
  """
  computed = poly1305_mac(key, message)

  # Constant-time comparison to prevent timing attacks
  if len(computed) != len(tag):
    return False

  result = 0
  for a, b in zip(computed, tag, strict=False):
    result |= a ^ b

  return result == 0


# Convenience function with alias name
poly1305 = poly1305_mac
