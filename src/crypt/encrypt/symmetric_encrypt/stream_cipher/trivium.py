"""Trivium stream cipher — pure Python implementation.

Key  : 80 bits (10 bytes)
IV   : 80 bits (10 bytes)
"""


class Trivium:
  """Trivium stream cipher state machine."""

  def __init__(self, key: bytes, iv: bytes) -> None:
    if len(key) != 10:
      msg = "Key must be 10 bytes (80 bits)"
      raise ValueError(msg)
    if len(iv) != 10:
      msg = "IV must be 10 bytes (80 bits)"
      raise ValueError(msg)
    # Load key/IV bits into registers (LSB first)
    key_bits = _bytes_to_bits(key)
    iv_bits = _bytes_to_bits(iv)
    # Three shift registers: s1 (93), s2 (84), s3 (111)
    self._s = [0] * 288
    for i in range(80):
      self._s[i] = key_bits[i]
      self._s[93 + i] = iv_bits[i]
    self._s[285] = self._s[286] = self._s[287] = 1
    # Warm-up: 4 * 288 = 1152 clock cycles
    for _ in range(4 * 288):
      self._clock(output=False)

  def _clock(self, output: bool = True) -> int:
    s = self._s
    t1 = s[65] ^ s[92]
    t2 = s[161] ^ s[176]
    t3 = s[242] ^ s[287]
    bit = (t1 ^ t2 ^ t3) if output else 0
    t1 ^= (s[90] & s[91]) ^ s[170]
    t2 ^= (s[174] & s[175]) ^ s[263]
    t3 ^= (s[285] & s[286]) ^ s[68]
    # Shift registers right
    self._s = [t3, *s[0:92], t1, *s[93:176], t2, *s[177:287]]
    return t1 ^ t2 ^ t3 if output else 0

  def keystream(self, length: int) -> bytes:
    """Generate *length* bytes of keystream."""
    bits: list[int] = []
    for _ in range(length * 8):
      bits.append(self._clock())
    return _bits_to_bytes(bits)

  def encrypt(self, data: bytes) -> bytes:
    """Encrypt (or decrypt) *data* by XOR with keystream."""
    ks = self.keystream(len(data))
    return bytes(a ^ b for a, b in zip(data, ks, strict=False))

  # decrypt == encrypt for stream ciphers
  decrypt = encrypt


def _bytes_to_bits(data: bytes) -> list[int]:
  bits = []
  for byte in data:
    for i in range(8):
      bits.append((byte >> i) & 1)
  return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
  result = bytearray()
  for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
      byte |= bits[i + j] << j
    result.append(byte)
  return bytes(result)


def trivium_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
  """Convenience function: encrypt *data* with Trivium."""
  return Trivium(key, iv).encrypt(data)


def trivium_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
  """Convenience function: decrypt *data* with Trivium."""
  return Trivium(key, iv).decrypt(data)
