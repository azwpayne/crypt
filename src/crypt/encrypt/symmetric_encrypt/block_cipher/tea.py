# TEA implementation
import struct


def tea_encrypt(data: bytes, key: bytes) -> bytes:
  if len(key) != 16:
    msg = "Key must be 16 bytes"
    raise ValueError(msg)
  padding_len = 8 - (len(data) % 8)
  padded = data + bytes([padding_len] * padding_len)
  result = bytearray()
  for i in range(0, len(padded), 8):
    v0, v1 = struct.unpack(">II", padded[i : i + 8])
    k0, k1, k2, k3 = struct.unpack(">IIII", key)
    delta, s = 0x9E3779B9, 0
    for _ in range(32):
      s = (s + delta) & 0xFFFFFFFF
      v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
      v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
    result.extend(struct.pack(">II", v0, v1))
  return bytes(result)


def tea_decrypt(cipher: bytes, key: bytes) -> bytes:
  if len(key) != 16 or len(cipher) % 8 != 0:
    msg = "Invalid input"
    raise ValueError(msg)
  result = bytearray()
  for i in range(0, len(cipher), 8):
    v0, v1 = struct.unpack(">II", cipher[i : i + 8])
    k0, k1, k2, k3 = struct.unpack(">IIII", key)
    delta = 0x9E3779B9
    s = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
      v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
      v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
      s = (s - delta) & 0xFFFFFFFF
    result.extend(struct.pack(">II", v0, v1))
  pad_len = result[-1]
  return bytes(result[:-pad_len])


class TEA:
  def __init__(self, key):
    self.key = (key if isinstance(key, bytes) else key.encode())[:16].ljust(16, b"\0")

  def encrypt(self, data):
    return tea_encrypt(data if isinstance(data, bytes) else data.encode(), self.key)

  def decrypt(self, data):
    return tea_decrypt(data, self.key)
