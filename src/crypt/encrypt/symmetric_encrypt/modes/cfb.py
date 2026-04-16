"""CFB (Cipher Feedback) Mode Implementation

CFB mode converts a block cipher into a self-synchronizing stream cipher.
A shift register is encrypted and the output is XORed with plaintext.
The ciphertext is fed back into the shift register.

Security Considerations:
- IV must be unique for each encryption with the same key. Never reuse an IV.
- IV does not need to be secret, but must be unpredictable (use a CSPRNG).
- CFB is self-synchronizing: transmission errors only affect a few blocks.
- No padding required: works with any plaintext length.
- For 8-bit CFB (segment_size=8), single bit errors affect one byte.

Usage Examples:
    >>> # Basic encryption with AES
    >>> from crypt.encrypt.symmetric_encrypt.modes.cfb import CFBMode
    >>> key = b'0123456789abcdef'  # 16 bytes for AES-128
    >>> iv = b'1234567890123456'   # 16 bytes (must match block size)
    >>> cfb = CFBMode(key=key, iv=iv)
    >>> plaintext = b"Hello, World!"
    >>> ciphertext = cfb.encrypt(plaintext)
    >>> cfb2 = CFBMode(key=key, iv=iv)
    >>> decrypted = cfb2.decrypt(ciphertext)
    >>> assert decrypted == plaintext

    >>> # Using with custom segment size (e.g., 1 byte = 8 bits)
    >>> cfb_8bit = CFBMode(key=key, iv=iv, segment_size=8)
    >>> ciphertext = cfb_8bit.encrypt(b"Secret message")
"""

from collections.abc import Callable
from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
  _encrypt_block,
  _get_key_params,
  key_expansion,
)
from typing import cast


class CFBMode:
  """CFB (Cipher Feedback) mode of operation.

  CFB mode encrypts the shift register and XORs the output with plaintext
  to produce ciphertext. The ciphertext is then fed back into the shift
  register, making this mode self-synchronizing.

  This mode provides:
  - Stream cipher properties: no padding required, any data length works
  - Self-synchronization: errors limited to a few blocks
  - Configurable segment size: can process 1 bit to full block at a time

  Attributes:
      block_size: The block size in bytes (16 for AES).
      key: The encryption key.
      iv: The initialization vector (initial shift register value).
      segment_size: The number of bits to process at a time (default 8).
      expanded_key: The expanded key schedule.
      nr: Number of rounds.

  Examples:
      >>> # Basic usage with AES
      >>> key = b'0123456789abcdef'
      >>> iv = b'1234567890123456'
      >>> cfb = CFBMode(key=key, iv=iv)
      >>> plaintext = b"Hello, World!"
      >>> ciphertext = cfb.encrypt(plaintext)
      >>> cfb2 = CFBMode(key=key, iv=iv)
      >>> decrypted = cfb2.decrypt(ciphertext)
      >>> decrypted == plaintext
      True

      >>> # Using 8-bit segment size (CFB-8)
      >>> cfb8 = CFBMode(key=key, iv=iv, segment_size=8)
      >>> ciphertext = cfb8.encrypt(b"Test")
      >>> CFBMode(key=key, iv=iv, segment_size=8).decrypt(ciphertext)
      b'Test'
  """

  def __init__(
    self,
    encrypt_func: Callable[[bytes], bytes] | None = None,
    block_size: int = 16,
    key: bytes | None = None,
    iv: bytes | None = None,
    segment_size: int = 8,
    **kwargs: object,
  ):
    """Initialize CFB mode.

    Args:
        encrypt_func: Optional external encrypt function.
        decrypt_func: Optional external decrypt function (not used in CFB).
        block_size: The block size in bytes (default 16 for AES).
        key: The encryption key (required if using AES).
        iv: The initialization vector (required, must match block_size).
        expanded_key: Pre-computed expanded key (optional).
        nr: Number of rounds (optional, derived from key if not provided).
        segment_size: Number of bits to process at a time (default 8).

    Raises:
        ValueError: If IV is not provided or has wrong length.
        ValueError: If key is not provided and no external functions are given.
        ValueError: If segment_size is invalid.

    Examples:
        >>> # Using AES key directly
        >>> cfb = CFBMode(key=b'0123456789abcdef', iv=b'1234567890123456')
        >>> ciphertext = cfb.encrypt(b"Hello")

        >>> # Using custom segment size (CFB-8)
        >>> cfb8 = CFBMode(
        ...     key=b'0123456789abcdef',
        ...     iv=b'1234567890123456',
        ...     segment_size=8
        ... )

        >>> # Using external cipher function
        >>> from Crypto.Cipher import AES
        >>> cipher = AES.new(b'0123456789abcdef', AES.MODE_ECB)
        >>> cfb = CFBMode(encrypt_func=cipher.encrypt, block_size=16,
        ...               iv=b'1234567890123456')
    """
    expanded_key = cast("list[int] | None", kwargs.get("expanded_key"))
    nr = cast("int | None", kwargs.get("nr"))
    if iv is None:
      msg = "IV is required for CFB mode"
      raise ValueError(msg)
    if len(iv) != block_size:
      msg = f"IV must be {block_size} bytes, got {len(iv)}"
      raise ValueError(msg)

    # Validate segment size
    if segment_size < 1 or segment_size > block_size * 8:
      msg = f"segment_size must be between 1 and {block_size * 8}"
      raise ValueError(msg)
    if segment_size % 8 != 0:
      msg = "segment_size must be a multiple of 8"
      raise ValueError(msg)

    self.block_size = block_size
    self.iv = iv
    self.segment_size = segment_size
    self._segment_bytes = segment_size // 8
    self._encrypt_func = encrypt_func
    self.key: bytes | None = None

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

  def _encrypt_shift_register(self, shift_reg: bytes) -> bytes:
    """Encrypt the shift register using the block cipher.

    Args:
        shift_reg: The current shift register value.

    Returns:
        The encrypted shift register.
    """
    if self._encrypt_func is not None:
      return self._encrypt_func(shift_reg)
    return _encrypt_block(shift_reg, self.expanded_key, self.nr)

  def encrypt(self, plaintext: bytes) -> bytes:
    """Encrypt data using CFB mode.

    Args:
        plaintext: The data to encrypt.

    Returns:
        The encrypted ciphertext.

    Examples:
        >>> cfb = CFBMode(key=b'0123456789abcdef', iv=b'1234567890123456')
        >>> ciphertext = cfb.encrypt(b"Hello, World!")
        >>> len(ciphertext) == len(b"Hello, World!")
        True
    """
    ciphertext = bytearray()
    shift_reg = self.iv

    for i in range(0, len(plaintext), self._segment_bytes):
      # Encrypt the shift register
      encrypted_sr = self._encrypt_shift_register(shift_reg)

      # Get the keystream segment (most significant bits)
      keystream = encrypted_sr[: self._segment_bytes]

      # Get plaintext segment
      segment = plaintext[i : i + self._segment_bytes]

      # XOR with keystream to get ciphertext segment
      cipher_segment = bytes([segment[j] ^ keystream[j] for j in range(len(segment))])
      ciphertext.extend(cipher_segment)

      # Update shift register: shift left and add ciphertext
      if self.segment_size == self.block_size * 8:
        # Full block: replace entire shift register
        shift_reg = cipher_segment.ljust(self.block_size, b"\x00")
      else:
        # Partial: shift left by segment bytes and add new ciphertext
        shift_reg = shift_reg[self._segment_bytes :] + cipher_segment.ljust(
          self._segment_bytes, b"\x00"
        )

    return bytes(ciphertext)

  def decrypt(self, ciphertext: bytes) -> bytes:
    """Decrypt data using CFB mode.

    Args:
        ciphertext: The data to decrypt.

    Returns:
        The decrypted plaintext.

    Examples:
        >>> key = b'0123456789abcdef'
        >>> iv = b'1234567890123456'
        >>> cfb = CFBMode(key=key, iv=iv)
        >>> ciphertext = cfb.encrypt(b"Hello, World!")
        >>> cfb2 = CFBMode(key=key, iv=iv)
        >>> cfb2.decrypt(ciphertext)
        b'Hello, World!'
    """
    plaintext = bytearray()
    shift_reg = self.iv

    for i in range(0, len(ciphertext), self._segment_bytes):
      # Encrypt the shift register (same as encryption)
      encrypted_sr = self._encrypt_shift_register(shift_reg)

      # Get the keystream segment
      keystream = encrypted_sr[: self._segment_bytes]

      # Get ciphertext segment
      segment = ciphertext[i : i + self._segment_bytes]

      # XOR with keystream to get plaintext segment
      plain_segment = bytes([segment[j] ^ keystream[j] for j in range(len(segment))])
      plaintext.extend(plain_segment)

      # Update shift register with ciphertext (same as encryption)
      if self.segment_size == self.block_size * 8:
        # Full block: replace entire shift register
        shift_reg = segment.ljust(self.block_size, b"\x00")
      else:
        # Partial: shift left by segment bytes and add new ciphertext
        shift_reg = shift_reg[self._segment_bytes :] + segment.ljust(
          self._segment_bytes, b"\x00"
        )

    return bytes(plaintext)


def test_cfb_mode():
  """Basic tests for CFB mode."""
  key = b"0123456789abcdef"
  iv = b"1234567890123456"

  cfb = CFBMode(key=key, iv=iv)

  # Test basic encryption/decryption
  plaintext = b"Hello, World!"
  ciphertext = cfb.encrypt(plaintext)
  decrypted = cfb.decrypt(ciphertext)
  assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

  # Test empty data
  empty = b""
  ciphertext = cfb.encrypt(empty)
  decrypted = cfb.decrypt(ciphertext)
  assert decrypted == empty

  # Test various lengths (no padding needed in CFB)
  for length in [1, 5, 15, 16, 17, 32]:
    cfb = CFBMode(key=key, iv=iv)
    data = b"a" * length
    ciphertext = cfb.encrypt(data)
    assert len(ciphertext) == length, f"Length mismatch for {length} bytes"
    cfb = CFBMode(key=key, iv=iv)
    decrypted = cfb.decrypt(ciphertext)
    assert decrypted == data, f"Decrypt failed for {length} bytes"

  print("All CFB mode tests passed!")


if __name__ == "__main__":
  test_cfb_mode()
