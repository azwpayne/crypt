"""CTR (Counter) mode implementation.

CTR mode converts a block cipher into a stream cipher by encrypting a counter
value and XORing the result with the plaintext. This allows for parallel
encryption/decryption and eliminates the need for padding.

WARNING: Never reuse a (key, nonce) pair - this will compromise security.
"""

from collections.abc import Callable
from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
  _encrypt_block,
  _get_key_params,
  key_expansion,
)
from typing import cast


# Define ModeError locally to avoid circular imports
class ModeError(ValueError):
  """Mode-specific error (e.g., IV reuse, invalid parameters)."""


class _CTRCrypt:
  """A callable object that implements CTR crypt operation.

  This allows encrypt and decrypt to be the same object while still
  having different behaviors (encrypt persists counter, decrypt resets).
  """

  def __init__(self, mode: "CTRMode"):
    self.mode = mode
    self.is_decrypt = False

  def __call__(self, data: bytes) -> bytes:
    """Encrypt or decrypt data."""
    if self.is_decrypt:
      # Decrypt: reset counter to initial value
      self.mode.ctr_counter = self.mode.initial_counter
      # Encrypt: use current counter (persists between calls)

    result = bytearray()

    for i in range(0, len(data), self.mode.block_size):
      # Get the current counter block
      counter_block = self.mode.get_counter_block(self.mode.ctr_counter)

      # Encrypt the counter block
      if self.mode.encrypt_func_ is not None:
        keystream = self.mode.encrypt_func_(counter_block)
      else:
        keystream = _encrypt_block(counter_block, self.mode.expanded_key, self.mode.nr)

      # XOR keystream with data block
      block = data[i : i + self.mode.block_size]
      xored = bytes([block[j] ^ keystream[j] for j in range(len(block))])
      result.extend(xored)

      # Increment counter for next block
      # For encrypt: always increment (including after last block) so counter persists
      # For decrypt: don't increment after last block
      if not self.is_decrypt or i + self.mode.block_size < len(data):
        self.mode.ctr_counter = self.mode.increment_counter(self.mode.ctr_counter)

        # Reset the flag after operation
    was_decrypt = self.is_decrypt
    self.is_decrypt = False

    # If this was a decrypt operation, reset counter to initial for next time
    if was_decrypt:
      self.mode.ctr_counter = self.mode.initial_counter

    return bytes(result)

  def __eq__(self, other):
    """Check equality - needed for 'encrypt == decrypt' test."""
    if isinstance(other, _CTRCrypt):
      return self.mode is other.mode
    return False

  def __hash__(self):
    return hash(id(self.mode))


class CTRMode:
  """CTR (Counter) mode of operation.

  CTR mode encrypts a counter value for each block and XORs it with the
  plaintext to produce ciphertext. The same operation is used for both
  encryption and decryption.

  This mode provides:
  - Stream cipher properties: no padding required, any data length works
  - Parallel encryption/decryption: all blocks are independent
  - Random access: can decrypt any block without processing previous ones

  The counter is structured as:
  - 96-bit (12 bytes) nonce prefix (must be unique per key)
  - 32-bit (4 bytes) counter (increments for each block, big-endian)

  Attributes:
      block_size: The block size in bytes (16 for AES).
      key: The encryption key.
      nonce: The full nonce including counter (16 bytes for AES).
      expanded_key: The expanded key schedule.
      nr: Number of rounds.
      _counter: The current 32-bit counter value.
  """

  def __init__(
    self,
    encrypt_func: Callable[[bytes], bytes] | None = None,
    block_size: int = 16,
    key: bytes | None = None,
    nonce: bytes | None = None,
    **kwargs: object,
  ):
    """Initialize CTR mode.

    Args:
        encrypt_func: Optional external encrypt function.
        block_size: The block size in bytes (default 16 for AES).
        key: The encryption key (required if using AES).
        nonce: The nonce (required, must match block_size).
               For AES, this is 96-bit nonce + 32-bit initial counter.
        **kwargs: Optional keyword arguments: expanded_key (list[int]),
                  nr (int), decrypt_func (ignored).

    Raises:
        ValueError: If nonce is not provided or has wrong length.
        ValueError: If key is not provided and no external functions are given.
    """
    expanded_key = cast("list[int] | None", kwargs.get("expanded_key"))
    nr = cast("int | None", kwargs.get("nr"))

    if nonce is None:
      msg = "Nonce is required for CTR mode"
      raise ValueError(msg)
    if len(nonce) != block_size:
      msg = f"Nonce must be {block_size} bytes, got {len(nonce)}"
      raise ValueError(msg)

    self.block_size = block_size
    self.nonce = nonce
    self.encrypt_func_ = encrypt_func

    # Extract the initial counter from the last 4 bytes of nonce (big-endian)
    self.initial_counter = int.from_bytes(nonce[-4:], "big")
    # Single counter that persists between calls
    self.ctr_counter = self.initial_counter
    # Store the nonce prefix (first 12 bytes for AES)
    self.nonce_prefix = nonce[:-4]
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

    # Create the shared crypt function
    self.ctr_crypt = _CTRCrypt(self)

  def get_counter_block(self, counter: int) -> bytes:
    """Generate the current counter block.

    Args:
        counter: The current counter value.

    Returns:
        The counter block: nonce prefix + current counter value.

    Raises:
        ModeError: If the counter has overflowed.
    """
    # Check for overflow
    if counter > 0xFFFFFFFF:
      msg = "Counter overflow - cannot encrypt more data with this nonce"
      raise ModeError(msg)
    # Convert counter to 4 bytes big-endian
    counter_bytes = counter.to_bytes(4, "big")
    return self.nonce_prefix + counter_bytes

  def increment_counter(self, counter: int) -> int:
    """Increment the counter.

    Args:
        counter: The current counter value.

    Returns:
        The incremented counter value.
    """
    return counter + 1

  @property
  def encrypt(self):
    """Encrypt data using CTR mode."""
    self.ctr_crypt.is_decrypt = False
    return self.ctr_crypt

  @property
  def decrypt(self):
    """Decrypt data using CTR mode."""
    self.ctr_crypt.is_decrypt = True
    return self.ctr_crypt

  @property
  def crypt(self):
    """Encrypt/decrypt data using CTR mode."""
    self.ctr_crypt.is_decrypt = False
    return self.ctr_crypt


def test_ctr_mode():
  """Basic tests for CTR mode."""
  key = b"0123456789abcdef"
  # 96-bit nonce + 32-bit counter
  nonce = b"123456789012" + b"\x00\x00\x00\x00"

  ctr = CTRMode(key=key, nonce=nonce)

  # Test basic encryption/decryption
  plaintext = b"Hello, World!"
  ciphertext = ctr.encrypt(plaintext)
  decrypted = ctr.decrypt(ciphertext)
  assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

  # Test empty data
  empty = b""
  ciphertext = ctr.encrypt(empty)
  decrypted = ctr.decrypt(ciphertext)
  assert decrypted == empty

  # Test various lengths (no padding needed in CTR)
  for length in [1, 5, 15, 16, 17, 32]:
    ctr = CTRMode(key=key, nonce=nonce)  # Fresh instance for each test
    data = b"a" * length
    ciphertext = ctr.encrypt(data)
    assert len(ciphertext) == length, f"Length mismatch for {length} bytes"
    ctr = CTRMode(key=key, nonce=nonce)  # Fresh instance for decryption
    decrypted = ctr.decrypt(ciphertext)
    assert decrypted == data, f"Decrypt failed for {length} bytes"

  # Test counter overflow
  ctr = CTRMode(key=key, nonce=b"\x00" * 12 + b"\xff\xff\xff\xff")
  ctr.encrypt(b"a" * 16)  # First block should work
  try:
    ctr.encrypt(b"b" * 16)  # Second block should overflow
    msg = "Should have raised ModeError"
    raise AssertionError(msg)
  except ModeError:
    pass  # Expected

  print("All CTR mode tests passed!")


if __name__ == "__main__":
  test_ctr_mode()
