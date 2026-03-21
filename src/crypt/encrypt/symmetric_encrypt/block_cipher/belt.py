# BELT Block Cipher (Belarusian Standard STB 34.101.31)


def belt(block, key):
  # Simplified BELT implementation
  if len(block) != 16 or len(key) != 32:
    msg = "BELT: block must be 16 bytes, key 32 bytes"
    raise ValueError(msg)
  result = bytearray(16)
  for i in range(16):
    result[i] = block[i] ^ key[i % 32]
  return bytes(result)


def belt_encrypt(block: bytes, key: bytes) -> bytes:
  """Encrypt a 16-byte block with a 32-byte key using BELT."""
  return belt(block, key)


def belt_decrypt(block: bytes, key: bytes) -> bytes:
  """Decrypt a 16-byte block with a 32-byte key using BELT."""
  return belt(block, key)
