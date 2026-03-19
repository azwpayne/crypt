"""CBC (Cipher Block Chaining) mode implementation.

CBC mode XORs each plaintext block with the previous ciphertext block before
encryption. For the first block, an Initialization Vector (IV) is used.

This provides semantic security: identical plaintext blocks produce different
ciphertext blocks due to the chaining mechanism.
"""

from collections.abc import Callable
from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
  _decrypt_block,
  _encrypt_block,
  _get_key_params,
  key_expansion,
)
from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import pad, unpad


class CBCMode:
  """CBC (Cipher Block Chaining) mode of operation.

  CBC encrypts each block of plaintext by first XORing it with the previous
  ciphertext block (or IV for the first block), then encrypting the result.

  This mode provides:
  - Semantic security: identical plaintext blocks produce different ciphertext
  - Error propagation: a single bit error in ciphertext affects two blocks
  - Parallel decryption: blocks can be decrypted in parallel

  Attributes:
      block_size: The block size in bytes (16 for AES).
      key: The encryption key.
      iv: The initialization vector.
      expanded_key: The expanded key schedule.
      nr: Number of rounds.
  """

  def __init__(
    self,
    encrypt_func: Callable[[bytes], bytes] | None = None,
    decrypt_func: Callable[[bytes], bytes] | None = None,
    block_size: int = 16,
    key: bytes | None = None,
    iv: bytes | None = None,
    **kwargs: object,
  ):
    """Initialize CBC mode.

    Args:
        encrypt_func: Optional external encrypt function.
        decrypt_func: Optional external decrypt function.
        block_size: The block size in bytes (default 16 for AES).
        key: The encryption key (required if using AES).
        iv: The initialization vector (required, must match block_size).
        expanded_key: Pre-computed expanded key (optional).
        nr: Number of rounds (optional, derived from key if not provided).

    Raises:
        ValueError: If IV is not provided or has wrong length.
        ValueError: If key is not provided and no external functions are given.
    """
    expanded_key: list[int] | None = kwargs.get("expanded_key")  # type: ignore[assignment]
    nr: int | None = kwargs.get("nr")  # type: ignore[assignment]
    if iv is None:
      msg = "IV is required for CBC mode"
      raise ValueError(msg)
    if len(iv) != block_size:
      msg = f"IV must be {block_size} bytes, got {len(iv)}"
      raise ValueError(msg)

    self.block_size = block_size
    self.iv = iv
    self._encrypt_func = encrypt_func
    self._decrypt_func = decrypt_func

    # If key is provided, use AES
    if key is not None:
      self.key = key
      _nk, self.nr = _get_key_params(key)
      self.expanded_key = (
        expanded_key if expanded_key is not None else key_expansion(key)
      )
    elif expanded_key is not None and nr is not None:
      self.key = None
      self.expanded_key = expanded_key
      self.nr = nr
    elif encrypt_func is None or decrypt_func is None:
      msg = "Either key or both encrypt_func and decrypt_func must be provided"
      raise ValueError(msg)
    else:
      self.key = None
      self.expanded_key = []
      self.nr = 0

  def encrypt(self, plaintext: bytes) -> bytes:
    """Encrypt data using CBC mode.

    Args:
        plaintext: The data to encrypt.

    Returns:
        The encrypted ciphertext.
    """
    # PKCS7 pad the plaintext
    padded = pad(plaintext, self.block_size)

    # Encrypt block by block
    ciphertext = bytearray()
    prev_block = self.iv

    for i in range(0, len(padded), self.block_size):
      block = padded[i : i + self.block_size]
      # XOR with previous ciphertext block (or IV for first block)
      xored = bytes([block[j] ^ prev_block[j] for j in range(self.block_size)])

      if self._encrypt_func is not None:
        encrypted_block = self._encrypt_func(xored)
      else:
        encrypted_block = _encrypt_block(xored, self.expanded_key, self.nr)

      ciphertext.extend(encrypted_block)
      prev_block = encrypted_block

    return bytes(ciphertext)

  def decrypt(self, ciphertext: bytes) -> bytes:
    """Decrypt data using CBC mode.

    Args:
        ciphertext: The data to decrypt.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If ciphertext length is not a multiple of block_size.
    """
    # Validate ciphertext length
    if len(ciphertext) % self.block_size != 0:
      msg = f"Ciphertext length must be a multiple of block_size ({self.block_size})"
      raise ValueError(msg)

    # Decrypt block by block
    plaintext = bytearray()
    prev_block = self.iv

    for i in range(0, len(ciphertext), self.block_size):
      block = ciphertext[i : i + self.block_size]

      if self._decrypt_func is not None:
        decrypted_block = self._decrypt_func(block)
      else:
        decrypted_block = _decrypt_block(block, self.expanded_key, self.nr)

      # XOR with previous ciphertext block (or IV for first block)
      xored = bytes(
        [decrypted_block[j] ^ prev_block[j] for j in range(self.block_size)]
      )
      plaintext.extend(xored)
      prev_block = block

    # PKCS7 unpad
    return unpad(bytes(plaintext), self.block_size)


def test_cbc_mode():
  """Basic tests for CBC mode."""
  key = b"0123456789abcdef"
  iv = b"1234567890123456"

  cbc = CBCMode(key=key, iv=iv)

  # Test basic encryption/decryption
  plaintext = b"Hello, World!"
  ciphertext = cbc.encrypt(plaintext)
  decrypted = cbc.decrypt(ciphertext)
  assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

  # Test empty data
  empty = b""
  ciphertext = cbc.encrypt(empty)
  decrypted = cbc.decrypt(ciphertext)
  assert decrypted == empty

  # Test exact block size
  exact_block = b"a" * 16
  ciphertext = cbc.encrypt(exact_block)
  assert len(ciphertext) == 32  # 2 blocks due to padding
  decrypted = cbc.decrypt(ciphertext)
  assert decrypted == exact_block

  # Test multi-block data
  multi_block = b"This is a test message that is longer than one block."
  ciphertext = cbc.encrypt(multi_block)
  decrypted = cbc.decrypt(ciphertext)
  assert decrypted == multi_block

  # Test that identical plaintext blocks produce different ciphertext
  identical_blocks = b"a" * 32  # Two identical 16-byte blocks
  ciphertext = cbc.encrypt(identical_blocks)
  block1 = ciphertext[:16]
  block2 = ciphertext[16:32]
  assert block1 != block2, (
    "CBC mode should produce different ciphertext for identical blocks"
  )

  print("All CBC mode tests passed!")


if __name__ == "__main__":
  test_cbc_mode()
