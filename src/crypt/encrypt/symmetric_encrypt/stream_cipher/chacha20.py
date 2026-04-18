"""Pure Python implementation of ChaCha20 stream cipher.

ChaCha20 is a stream cipher designed by Daniel J. Bernstein.
It is a variant of Salsa20 with improved diffusion and resistance
to cryptographic attacks.

Reference: RFC 8439
"""

import struct


def _xor_bytes(a: bytes, b: bytes) -> bytes:
  """XOR two byte strings together."""
  return bytes(x ^ y for x, y in zip(a, b, strict=False))


def rotl(v: int, n: int) -> int:
  """Rotate a 32-bit unsigned integer left by n bits."""
  return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
  """ChaCha20 quarter round function operating on positions a, b, c, d."""
  x[a] = (x[a] + x[b]) & 0xFFFFFFFF
  x[d] = rotl(x[d] ^ x[a], 16)
  x[c] = (x[c] + x[d]) & 0xFFFFFFFF
  x[b] = rotl(x[b] ^ x[c], 12)
  x[a] = (x[a] + x[b]) & 0xFFFFFFFF
  x[d] = rotl(x[d] ^ x[a], 8)
  x[c] = (x[c] + x[d]) & 0xFFFFFFFF
  x[b] = rotl(x[b] ^ x[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
  """Generate a 64-byte ChaCha20 block.

  Args:
      key: 32-byte key
      counter: Block counter value
      nonce: 12-byte nonce

  Returns:
      64-byte keystream block
  """
  # ChaCha20 constant "expand 32-byte k"
  constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
  key_words = list(struct.unpack("<8I", key))
  nonce_words = list(struct.unpack("<3I", nonce))

  # Construct initial state: 16 x 32-bit integers
  state = [0] * 16
  state[:4] = constants
  state[4:12] = key_words
  state[12] = counter & 0xFFFFFFFF
  state[13:16] = nonce_words

  working_state = state.copy()

  # Perform 20 rounds (10 double rounds: column + diagonal)
  for _ in range(10):
    _column_diagonal_rounds(working_state)
  # Add original state to working state
  for i in range(16):
    working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

  # Pack 16 x 32-bit integers as little-endian 64 bytes
  return struct.pack("<16L", *working_state)


def _column_diagonal_rounds(working_state: list[int]) -> None:
  """Perform one round of column and diagonal operations."""
  # Column rounds
  quarter_round(working_state, 0, 4, 8, 12)
  quarter_round(working_state, 1, 5, 9, 13)
  quarter_round(working_state, 2, 6, 10, 14)
  quarter_round(working_state, 3, 7, 11, 15)
  # Diagonal rounds
  quarter_round(working_state, 0, 5, 10, 15)
  quarter_round(working_state, 1, 6, 11, 12)
  quarter_round(working_state, 2, 7, 8, 13)
  quarter_round(working_state, 3, 4, 9, 14)


def chacha20_encrypt(key: bytes, nonce: bytes, counter: int, plaintext: bytes) -> bytes:
  """Encrypt plaintext using ChaCha20.

  Args:
      key: 32-byte key
      nonce: 12-byte nonce
      counter: Initial counter value (usually 0)
      plaintext: Data to encrypt

  Returns:
      Ciphertext bytes
  """
  ciphertext = bytearray()
  # Each block is 64 bytes; if plaintext is shorter, use partial keystream
  block_count = (len(plaintext) + 63) // 64
  for i in range(block_count):
    keystream = chacha20_block(key, counter + i, nonce)
    block = plaintext[i * 64 : (i + 1) * 64]
    # XOR operation
    for j in range(len(block)):
      ciphertext.append(block[j] ^ keystream[j])
  return bytes(ciphertext)


def chacha20_decrypt(
  key: bytes, nonce: bytes, counter: int, ciphertext: bytes
) -> bytes:
  """Decrypt ciphertext using ChaCha20.

  ChaCha20 is a stream cipher - encryption and decryption are the same operation.

  Args:
      key: 32-byte key
      nonce: 12-byte nonce
      counter: Initial counter value (usually 0)
      ciphertext: Data to decrypt

  Returns:
      Plaintext bytes
  """
  return chacha20_encrypt(key, nonce, counter, ciphertext)


# Example: Encryption and decryption test
# Plaintext: 30313233343536373839
# Ciphertext (hex): a3e365d72defcc690ef2
# Decrypted plaintext: 30313233343536373839
if __name__ == "__main__":
  # Example key (32 bytes) and nonce (12 bytes)
  test_key = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  )
  test_nonce = bytes.fromhex("202122232425262728292a2b")
  test_counter = 0
  test_plaintext = bytes.fromhex("30313233343536373839")
  print("Plaintext:", test_plaintext.hex())

  # Encrypt
  test_ciphertext = chacha20_encrypt(test_key, test_nonce, test_counter, test_plaintext)
  print("Ciphertext (hex):", test_ciphertext.hex())

  # Decrypt: XOR ciphertext with same keystream to recover plaintext
  decrypted = chacha20_encrypt(test_key, test_nonce, test_counter, test_ciphertext)
  print("Decrypted plaintext:", decrypted.hex())
