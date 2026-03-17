"""OFB (Output Feedback) mode implementation.

OFB mode generates a keystream independent of plaintext by repeatedly encrypting
an initialization vector. The keystream is XORed with plaintext to produce
ciphertext. This provides no error propagation in the ciphertext.
"""

from collections.abc import Callable
from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
  _encrypt_block,
  _get_key_params,
  key_expansion,
)


class OFBMode:
  """OFB (Output Feedback) mode of operation.

  OFB mode creates a keystream by repeatedly encrypting an initialization
  vector. The keystream is XORed with plaintext to produce ciphertext.

  This mode provides:
  - Stream cipher properties: no padding required, any data length works
  - No error propagation: bit errors in ciphertext affect only corresponding plaintext bits
  - Parallel decryption: all blocks are independent
  - Precomputable keystream: encryption can be done without plaintext

  Attributes:
      block_size: The block size in bytes (16 for AES).
      key: The encryption key.
      iv: The initialization vector (initial feedback value).
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
    expanded_key: list[int] | None = None,
    nr: int | None = None,
  ):
    """Initialize OFB mode.

    Args:
        encrypt_func: Optional external encrypt function.
        decrypt_func: Optional external decrypt function (not used in OFB).
        block_size: The block size in bytes (default 16 for AES).
        key: The encryption key (required if using AES).
        iv: The initialization vector (required, must match block_size).
        expanded_key: Pre-computed expanded key (optional).
        nr: Number of rounds (optional, derived from key if not provided).

    Raises:
        ValueError: If IV is not provided or has wrong length.
        ValueError: If key is not provided and no external functions are given.
    """
    if iv is None:
      msg = "IV is required for OFB mode"
      raise ValueError(msg)
    if len(iv) != block_size:
      msg = f"IV must be {block_size} bytes, got {len(iv)}"
      raise ValueError(msg)

    self.block_size = block_size
    self.iv = iv
    self._encrypt_func = encrypt_func

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
    elif encrypt_func is None:
      msg = "Either key or encrypt_func must be provided"
      raise ValueError(msg)
    else:
      self.key = None
      self.expanded_key = []
      self.nr = 0

  def _generate_keystream(self, length: int) -> bytes:
    """Generate keystream of specified length.

    Args:
        length: The number of bytes of keystream to generate.

    Returns:
        The generated keystream.
    """
    keystream = bytearray()
    feedback = self.iv

    while len(keystream) < length:
      # Encrypt the feedback value
      if self._encrypt_func is not None:
        encrypted = self._encrypt_func(feedback)
      else:
        encrypted = _encrypt_block(feedback, self.expanded_key, self.nr)

      keystream.extend(encrypted)
      feedback = encrypted

    return bytes(keystream[:length])

  def encrypt(self, plaintext: bytes) -> bytes:
    """Encrypt data using OFB mode.

    Args:
        plaintext: The data to encrypt.

    Returns:
        The encrypted ciphertext.
    """
    keystream = self._generate_keystream(len(plaintext))

    # XOR plaintext with keystream
    return bytes([plaintext[i] ^ keystream[i] for i in range(len(plaintext))])

  def decrypt(self, ciphertext: bytes) -> bytes:
    """Decrypt data using OFB mode.

    Args:
        ciphertext: The data to decrypt.

    Returns:
        The decrypted plaintext.
    """
    # OFB decryption is identical to encryption (both XOR with keystream)
    keystream = self._generate_keystream(len(ciphertext))

    # XOR ciphertext with keystream
    return bytes([ciphertext[i] ^ keystream[i] for i in range(len(ciphertext))])


def test_ofb_mode():
  """Basic tests for OFB mode."""
  key = b"0123456789abcdef"
  iv = b"1234567890123456"

  ofb = OFBMode(key=key, iv=iv)

  # Test basic encryption/decryption
  plaintext = b"Hello, World!"
  ciphertext = ofb.encrypt(plaintext)
  decrypted = ofb.decrypt(ciphertext)
  assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

  # Test empty data
  empty = b""
  ciphertext = ofb.encrypt(empty)
  decrypted = ofb.decrypt(ciphertext)
  assert decrypted == empty

  # Test various lengths (no padding needed in OFB)
  for length in [1, 5, 15, 16, 17, 32]:
    ofb = OFBMode(key=key, iv=iv)
    data = b"a" * length
    ciphertext = ofb.encrypt(data)
    assert len(ciphertext) == length, f"Length mismatch for {length} bytes"
    ofb = OFBMode(key=key, iv=iv)
    decrypted = ofb.decrypt(ciphertext)
    assert decrypted == data, f"Decrypt failed for {length} bytes"

  print("All OFB mode tests passed!")


if __name__ == "__main__":
  test_ofb_mode()
