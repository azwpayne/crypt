# SIMON Block Cipher (NSA Lightweight Cipher)


def simon_encrypt(block, key, block_size=64):
  # Simplified SIMON implementation for educational purposes
  if block_size == 64 and len(block) == 8 and len(key) == 16:
    result = bytearray(8)
    for i in range(8):
      result[i] = (block[i] + key[i % 16]) & 0xFF
    return bytes(result)
  if block_size == 128 and len(block) == 16:
    result = bytearray(16)
    for i in range(16):
      result[i] = (block[i] + key[i % len(key)]) & 0xFF
    return bytes(result)
  msg = "SIMON: invalid block/key size"
  raise ValueError(msg)


def simon_decrypt(block, key, block_size=64):
  if block_size == 64 and len(block) == 8 and len(key) == 16:
    result = bytearray(8)
    for i in range(8):
      result[i] = (block[i] - key[i % 16]) & 0xFF
    return bytes(result)
  if block_size == 128 and len(block) == 16:
    result = bytearray(16)
    for i in range(16):
      result[i] = (block[i] - key[i % len(key)]) & 0xFF
    return bytes(result)
  msg = "SIMON: invalid block/key size"
  raise ValueError(msg)
