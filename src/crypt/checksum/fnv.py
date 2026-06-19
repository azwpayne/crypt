"""FNV (Fowler–Noll–Vo) hash functions — pure Python implementation.

Variants: FNV-1 and FNV-1a for 32, 64, and 128 bit output.
FNV-1a XORs before multiplying; FNV-1 multiplies before XORing.
"""

# FNV parameters
_PARAMS = {
  32: (0x811C9DC5, 0x01000193),
  64: (0xCBF29CE484222325, 0x100000001B3),
  128: (0x6C62272E07BB0142628B408779AEF38F, 0x0000000001000000000000000000013B),
}


def fnv1(data: bytes, bits: int = 32) -> int:
  """FNV-1 hash: multiply then XOR."""
  basis, prime = _PARAMS[bits]
  mask = (1 << bits) - 1
  h = basis
  for byte in data:
    h = (h * prime) & mask
    h ^= byte
  return h


def fnv1a(data: bytes, bits: int = 32) -> int:
  """FNV-1a hash: XOR then multiply (better avalanche than FNV-1)."""
  basis, prime = _PARAMS[bits]
  mask = (1 << bits) - 1
  h = basis
  for byte in data:
    h ^= byte
    h = (h * prime) & mask
  return h


# Convenience wrappers
def fnv1_32(data: bytes) -> int:
  return fnv1(data, 32)


def fnv1a_32(data: bytes) -> int:
  return fnv1a(data, 32)


def fnv1_64(data: bytes) -> int:
  return fnv1(data, 64)


def fnv1a_64(data: bytes) -> int:
  return fnv1a(data, 64)


def fnv1_128(data: bytes) -> int:
  return fnv1(data, 128)


def fnv1a_128(data: bytes) -> int:
  return fnv1a(data, 128)
