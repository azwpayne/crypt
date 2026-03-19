# @author  : azwpayne(https://github.com/azwpayne)
# @name    : 3DES.py
# @time    : 2026/3/15 12:00 Sun
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 3DES (Triple DES) block cipher implementation

"""
3DES (Triple DES / TDEA) Block Cipher Implementation.

This module implements 3DES with EDE (Encrypt-Decrypt-Encrypt) mode:
- 3DES-EDE2: Two-key variant (K1, K2, K1) - 16 bytes
- 3DES-EDE3: Three-key variant (K1, K2, K3) - 24 bytes

3DES applies DES three times with different keys to increase security.
Effective key length: 112 bits (2-key) or 168 bits (3-key).
"""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.block_cipher.des import (
  DES,
  _bytes_to_int,
  _int_to_bytes,
  _pkcs7_pad,
  _pkcs7_unpad,
)


class DES3:
  """
  3DES (Triple DES / TDEA) block cipher.

  Implements EDE (Encrypt-Decrypt-Encrypt) mode:
  - Encryption: Encrypt(K1) -> Decrypt(K2) -> Encrypt(K3)
  - Decryption: Decrypt(K3) -> Encrypt(K2) -> Decrypt(K1)

  For 2-key 3DES: K3 = K1
  For 3-key 3DES: K1, K2, K3 are all different

  Supports ECB and CBC modes with PKCS7 padding.
  """

  BLOCK_SIZE = 8  # 64 bits

  def __init__(self, key: bytes) -> None:
    """
    Initialize 3DES cipher with a key.

    Args:
        key: 16 bytes for 2-key 3DES (K1, K2, K1)
             24 bytes for 3-key 3DES (K1, K2, K3)

    Raises:
        ValueError: If key is not 16 or 24 bytes
    """
    if len(key) not in (16, 24):
      msg = f"Key must be 16 or 24 bytes, got {len(key)}"
      raise ValueError(msg)

    self.key = key

    # Split key into components
    if len(key) == 16:
      # 2-key 3DES: K1, K2, K1
      self.k1 = key[:8]
      self.k2 = key[8:16]
      self.k3 = self.k1
    else:
      # 3-key 3DES: K1, K2, K3
      self.k1 = key[:8]
      self.k2 = key[8:16]
      self.k3 = key[16:24]

    # Create DES instances for each key
    self.des1 = DES(self.k1)
    self.des2 = DES(self.k2)
    self.des3 = DES(self.k3)

  def _ede_encrypt_block(self, block: int) -> int:
    """
    Encrypt a single block using EDE (Encrypt-Decrypt-Encrypt).

    Args:
        block: 64-bit block as integer

    Returns:
        Encrypted 64-bit block as integer
    """
    # EDE: Encrypt(K1) -> Decrypt(K2) -> Encrypt(K3)
    result = _des_block_encrypt(block, self.des1.subkeys)
    result = _des_block_decrypt(result, self.des2.subkeys)
    return _des_block_encrypt(result, self.des3.subkeys)

  def _ede_decrypt_block(self, block: int) -> int:
    """
    Decrypt a single block using EDE (Decrypt-Encrypt-Decrypt).

    Args:
        block: 64-bit block as integer

    Returns:
        Decrypted 64-bit block as integer
    """
    # EDE decryption: Decrypt(K3) -> Encrypt(K2) -> Decrypt(K1)
    result = _des_block_decrypt(block, self.des3.subkeys)
    result = _des_block_encrypt(result, self.des2.subkeys)
    return _des_block_decrypt(result, self.des1.subkeys)

  def encrypt_ecb(self, plaintext: bytes) -> bytes:
    """
    Encrypt data using ECB mode.

    Args:
        plaintext: Data to encrypt (will be padded to 8-byte blocks)

    Returns:
        Encrypted ciphertext
    """
    # Pad the plaintext
    padded = _pkcs7_pad(plaintext, self.BLOCK_SIZE)

    ciphertext = bytearray()
    for i in range(0, len(padded), self.BLOCK_SIZE):
      block = padded[i : i + self.BLOCK_SIZE]
      block_int = _bytes_to_int(block)
      encrypted_int = self._ede_encrypt_block(block_int)
      ciphertext.extend(_int_to_bytes(encrypted_int, self.BLOCK_SIZE))

    return bytes(ciphertext)

  def decrypt_ecb(self, ciphertext: bytes) -> bytes:
    """
    Decrypt data using ECB mode.

    Args:
        ciphertext: Data to decrypt (must be multiple of 8 bytes)

    Returns:
        Decrypted plaintext (padding removed)
    """
    if len(ciphertext) % self.BLOCK_SIZE != 0:
      msg = f"Ciphertext must be multiple of {self.BLOCK_SIZE} bytes"
      raise ValueError(msg)

    plaintext = bytearray()
    for i in range(0, len(ciphertext), self.BLOCK_SIZE):
      block = ciphertext[i : i + self.BLOCK_SIZE]
      block_int = _bytes_to_int(block)
      decrypted_int = self._ede_decrypt_block(block_int)
      plaintext.extend(_int_to_bytes(decrypted_int, self.BLOCK_SIZE))

    # Remove padding
    return _pkcs7_unpad(bytes(plaintext))

  def encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
    """
    Encrypt data using CBC mode.

    Args:
        plaintext: Data to encrypt
        iv: 8-byte initialization vector

    Returns:
        Encrypted ciphertext
    """
    if len(iv) != self.BLOCK_SIZE:
      msg = f"IV must be {self.BLOCK_SIZE} bytes"
      raise ValueError(msg)

    # Pad the plaintext
    padded = _pkcs7_pad(plaintext, self.BLOCK_SIZE)

    ciphertext = bytearray()
    prev_block = _bytes_to_int(iv)

    for i in range(0, len(padded), self.BLOCK_SIZE):
      block = padded[i : i + self.BLOCK_SIZE]
      block_int = _bytes_to_int(block)

      # XOR with previous ciphertext block (or IV)
      xored = block_int ^ prev_block

      # Encrypt with EDE
      encrypted_int = self._ede_encrypt_block(xored)
      ciphertext.extend(_int_to_bytes(encrypted_int, self.BLOCK_SIZE))

      # Update previous block
      prev_block = encrypted_int

    return bytes(ciphertext)

  def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
    """
    Decrypt data using CBC mode.

    Args:
        ciphertext: Data to decrypt (must be multiple of 8 bytes)
        iv: 8-byte initialization vector

    Returns:
        Decrypted plaintext (padding removed)
    """
    if len(iv) != self.BLOCK_SIZE:
      msg = f"IV must be {self.BLOCK_SIZE} bytes"
      raise ValueError(msg)
    if len(ciphertext) % self.BLOCK_SIZE != 0:
      msg = f"Ciphertext must be multiple of {self.BLOCK_SIZE} bytes"
      raise ValueError(msg)

    plaintext = bytearray()
    prev_block = _bytes_to_int(iv)

    for i in range(0, len(ciphertext), self.BLOCK_SIZE):
      block = ciphertext[i : i + self.BLOCK_SIZE]
      block_int = _bytes_to_int(block)

      # Decrypt with EDE
      decrypted_int = self._ede_decrypt_block(block_int)

      # XOR with previous ciphertext block (or IV)
      xored = decrypted_int ^ prev_block
      plaintext.extend(_int_to_bytes(xored, self.BLOCK_SIZE))

      # Update previous block
      prev_block = block_int

    # Remove padding
    return _pkcs7_unpad(bytes(plaintext))


def _permute(block: int, table: list[int], input_bits: int) -> int:
  """Apply a permutation table to a block of bits."""
  result = 0
  for i, bit_pos in enumerate(table):
    # bit_pos is 1-indexed in DES tables
    bit = (block >> (input_bits - bit_pos)) & 1
    result |= bit << (len(table) - 1 - i)
  return result


def _left_rotate(value: int, bits: int, size: int) -> int:
  """Left rotate a value by specified bits."""
  mask = (1 << size) - 1
  return ((value << bits) | (value >> (size - bits))) & mask


def _s_box_substitution(block: int) -> int:
  """Apply S-box substitution to a 48-bit block, producing 32 bits."""
  from crypt.encrypt.symmetric_encrypt.block_cipher.des import S_BOXES

  result = 0
  for i in range(8):
    # Extract 6-bit chunk
    chunk = (block >> (42 - i * 6)) & 0x3F

    # Get row (bits 5 and 0) and column (bits 1-4)
    row = ((chunk >> 4) & 2) | (chunk & 1)
    col = (chunk >> 1) & 0xF

    # S-box lookup
    s_value = S_BOXES[i][row][col]
    result |= s_value << (28 - i * 4)

  return result


def _feistel_function(right: int, subkey: int) -> int:
  """
  The Feistel (F) function.
  Expands 32 bits to 48, XORs with subkey, S-box substitution, P-permutation.
  """
  from crypt.encrypt.symmetric_encrypt.block_cipher.des import (
    E_TABLE,
    P_TABLE,
  )

  # Expansion: 32 bits -> 48 bits
  expanded = _permute(right, E_TABLE, 32)

  # XOR with subkey
  xored = expanded ^ subkey

  # S-box substitution: 48 bits -> 32 bits
  substituted = _s_box_substitution(xored)

  # P-permutation: 32 bits -> 32 bits
  return _permute(substituted, P_TABLE, 32)


def _des_block_encrypt(block: int, subkeys: list[int]) -> int:
  """Encrypt a single 64-bit block using DES."""
  from crypt.encrypt.symmetric_encrypt.block_cipher.des import (
    FP_TABLE,
    IP_TABLE,
  )

  # Initial Permutation
  block = _permute(block, IP_TABLE, 64)

  # Split into left and right halves (32 bits each)
  left = (block >> 32) & 0xFFFFFFFF
  right = block & 0xFFFFFFFF

  # 16 rounds of Feistel network
  for i in range(16):
    # Save current right
    new_right = left ^ _feistel_function(right, subkeys[i])
    left = right
    right = new_right

  # Final swap (undo the last swap)
  block = (right << 32) | left

  # Final Permutation
  return _permute(block, FP_TABLE, 64)


def _des_block_decrypt(block: int, subkeys: list[int]) -> int:
  """Decrypt a single 64-bit block using DES."""
  from crypt.encrypt.symmetric_encrypt.block_cipher.des import (
    FP_TABLE,
    IP_TABLE,
  )

  # Initial Permutation
  block = _permute(block, IP_TABLE, 64)

  # Split into left and right halves
  left = (block >> 32) & 0xFFFFFFFF
  right = block & 0xFFFFFFFF

  # 16 rounds of Feistel network (with subkeys in reverse order)
  for i in range(15, -1, -1):
    new_right = left ^ _feistel_function(right, subkeys[i])
    left = right
    right = new_right

  # Final swap
  block = (right << 32) | left

  # Final Permutation
  return _permute(block, FP_TABLE, 64)


def des3_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
  """
  Convenience function for 3DES encryption.

  Args:
      plaintext: Data to encrypt
      key: 16-byte (2-key) or 24-byte (3-key) key
      iv: Optional 8-byte IV for CBC mode (if None, ECB is used)

  Returns:
      Encrypted ciphertext
  """
  des3 = DES3(key)
  if iv is None:
    return des3.encrypt_ecb(plaintext)
  return des3.encrypt_cbc(plaintext, iv)


def des3_decrypt(ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
  """
  Convenience function for 3DES decryption.

  Args:
      ciphertext: Data to decrypt
      key: 16-byte (2-key) or 24-byte (3-key) key
      iv: Optional 8-byte IV for CBC mode (if None, ECB is used)

  Returns:
      Decrypted plaintext
  """
  des3 = DES3(key)
  if iv is None:
    return des3.decrypt_ecb(ciphertext)
  return des3.decrypt_cbc(ciphertext, iv)


if __name__ == "__main__":
  # Test vectors
  # 2-key 3DES (EDE2)
  key2 = b"0123456789abcdef"  # 16 bytes
  iv = b"00000000"
  plaintext = b"hello wo"  # Exactly 8 bytes

  des3_2key = DES3(key2)

  # ECB mode test with 2-key
  encrypted = des3_2key.encrypt_ecb(plaintext)
  decrypted = des3_2key.decrypt_ecb(encrypted)
  print(f"3DES-EDE2 ECB: {plaintext!r} -> {encrypted.hex()} -> {decrypted!r}")

  # CBC mode test with 2-key
  encrypted = des3_2key.encrypt_cbc(plaintext, iv)
  decrypted = des3_2key.decrypt_cbc(encrypted, iv)
  print(f"3DES-EDE2 CBC: {plaintext!r} -> {encrypted.hex()} -> {decrypted!r}")

  # 3-key 3DES (EDE3)
  key3 = b"0123456789abcdef01234567"  # 24 bytes
  des3_3key = DES3(key3)

  # ECB mode test with 3-key
  encrypted3 = des3_3key.encrypt_ecb(plaintext)
  decrypted3 = des3_3key.decrypt_ecb(encrypted3)
  print(f"3DES-EDE3 ECB: {plaintext!r} -> {encrypted3.hex()} -> {decrypted3!r}")

  # CBC mode test with 3-key
  encrypted3 = des3_3key.encrypt_cbc(plaintext, iv)
  decrypted3 = des3_3key.decrypt_cbc(encrypted3, iv)
  print(f"3DES-EDE3 CBC: {plaintext!r} -> {encrypted3.hex()} -> {decrypted3!r}")

  # Longer plaintext test
  plaintext2 = b"hello world!!!!!"
  encrypted2 = des3_2key.encrypt_cbc(plaintext2, iv)
  decrypted2 = des3_2key.decrypt_cbc(encrypted2, iv)
  print(f"3DES-EDE2 CBC long: {plaintext2!r} -> {encrypted2.hex()} -> {decrypted2!r}")
