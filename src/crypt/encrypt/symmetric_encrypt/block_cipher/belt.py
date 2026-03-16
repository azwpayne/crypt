# BELT Block Cipher (Belarusian Standard STB 34.101.31)


def belt_encrypt(block, key):
  # Simplified BELT implementation
  if len(block) != 16 or len(key) != 32:
    msg = "BELT: block must be 16 bytes, key 32 bytes"
    raise ValueError(msg)
  result = bytearray(16)
  for i in range(16):
    result[i] = block[i] ^ key[i % 32]
  return bytes(result)


def belt_decrypt(block, key):
  if len(block) != 16 or len(key) != 32:
    msg = "BELT: block must be 16 bytes, key 32 bytes"
    raise ValueError(msg)
  result = bytearray(16)
  for i in range(16):
    result[i] = block[i] ^ key[i % 32]
  return bytes(result)
