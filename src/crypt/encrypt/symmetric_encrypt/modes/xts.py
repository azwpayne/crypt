"""XTS (XEX-based Tweaked Codebook) mode implementation.

XTS mode is designed for disk encryption. It uses a single key that is internally
split into two keys: one for data encryption and one for tweak encryption.
It supports ciphertext stealing for partial final blocks.

Note: This is an educational implementation. For production use, please use
well-established cryptographic libraries.
"""

from collections.abc import Callable
from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
  _decrypt_block,
  _encrypt_block,
  _get_key_params,
  key_expansion,
)


class XTSMode:
  """XTS (XEX-based Tweaked Codebook) mode of operation."""

  def __init__(  # noqa: PLR0913
    self,
    encrypt_func: Callable[[bytes], bytes] | None = None,
    decrypt_func: Callable[[bytes], bytes] | None = None,
    block_size: int = 16,
    key: bytes | None = None,
    expanded_key: list[int] | None = None,
    nr: int | None = None,
  ):
    """Initialize XTS mode."""
    self.block_size = block_size
    self._encrypt_func = encrypt_func
    self._decrypt_func = decrypt_func

    if key is not None:
      if len(key) % 2 != 0:
        msg = "Key length must be even for XTS mode"
        raise ValueError(msg)

      self.key = key
      half_len = len(key) // 2
      key1 = key[:half_len]
      key2 = key[half_len:]

      _, self.nr1 = _get_key_params(key1)
      _, self.nr2 = _get_key_params(key2)

      self.expanded_key1 = key_expansion(key1)
      self.expanded_key2 = key_expansion(key2)
    elif expanded_key is not None and nr is not None:
      self.key = None
      self.expanded_key1 = expanded_key
      self.expanded_key2 = expanded_key
      self.nr1 = nr
      self.nr2 = nr
    elif encrypt_func is None or decrypt_func is None:
      msg = "Either key or both encrypt_func and decrypt_func must be provided"
      raise ValueError(msg)
    else:
      self.key = None
      self.expanded_key1 = []
      self.expanded_key2 = []
      self.nr1 = 0
      self.nr2 = 0

  def _encrypt_block(self, block: bytes, key: list[int], nr: int) -> bytes:
    """Encrypt a single block."""
    if self._encrypt_func is not None:
      return self._encrypt_func(block)
    return _encrypt_block(block, key, nr)

  def _decrypt_block(self, block: bytes, key: list[int], nr: int) -> bytes:
    """Decrypt a single block."""
    if self._decrypt_func is not None:
      return self._decrypt_func(block)
    return _decrypt_block(block, key, nr)

  def _gf_mul_alpha(self, t: int) -> int:
    """Multiply by alpha (x) in GF(2^128)."""
    carry = (t >> 127) & 1
    t = (t << 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    if carry:
      t ^= 0x87
    return t

  def _compute_tweak_values(self, tweak: bytes, num_blocks: int) -> list[int]:
    """Compute tweak values for all blocks."""
    # Pad tweak to block size
    if len(tweak) < self.block_size:
      tweak = tweak.rjust(self.block_size, b"\x00")
    elif len(tweak) > self.block_size:
      tweak = tweak[: self.block_size]

    # Encrypt tweak with key2
    t = int.from_bytes(self._encrypt_block(tweak, self.expanded_key2, self.nr2), "big")

    # Compute tweak values for each block
    tweaks = [t]
    for _ in range(num_blocks - 1):
      t = self._gf_mul_alpha(t)
      tweaks.append(t)

    return tweaks

  def _xex_encrypt(self, block: bytes, tweak_int: int) -> bytes:
    """XEX encryption: XOR with tweak, encrypt, XOR with tweak."""
    t_bytes = tweak_int.to_bytes(16, "big")
    xored = bytes([block[j] ^ t_bytes[j] for j in range(self.block_size)])
    encrypted = self._encrypt_block(xored, self.expanded_key1, self.nr1)
    return bytes([encrypted[j] ^ t_bytes[j] for j in range(self.block_size)])

  def _xex_decrypt(self, block: bytes, tweak_int: int) -> bytes:
    """XEX decryption: XOR with tweak, decrypt, XOR with tweak."""
    t_bytes = tweak_int.to_bytes(16, "big")
    xored = bytes([block[j] ^ t_bytes[j] for j in range(self.block_size)])
    decrypted = self._decrypt_block(xored, self.expanded_key1, self.nr1)
    return bytes([decrypted[j] ^ t_bytes[j] for j in range(self.block_size)])

  def encrypt(self, plaintext: bytes, tweak: bytes) -> bytes:
    """Encrypt data using XTS mode."""
    if len(plaintext) == 0:
      return b""

    # Handle less than one block: use as stream cipher
    # Generate keystream by encrypting zero block, then XOR
    if len(plaintext) < self.block_size:
      tweaks = self._compute_tweak_values(tweak, 1)
      zero_block = bytes(self.block_size)
      keystream = self._xex_encrypt(zero_block, tweaks[0])
      return bytes([plaintext[i] ^ keystream[i] for i in range(len(plaintext))])

    # Handle exact block size - standard XTS encryption
    if len(plaintext) == self.block_size:
      tweaks = self._compute_tweak_values(tweak, 1)
      return self._xex_encrypt(plaintext, tweaks[0])

    # Calculate number of full blocks and partial bytes
    num_full_blocks = len(plaintext) // self.block_size
    partial_len = len(plaintext) % self.block_size

    if partial_len == 0:
      # No partial block - standard XTS encryption
      tweaks = self._compute_tweak_values(tweak, num_full_blocks)
      ciphertext = bytearray()
      for i in range(num_full_blocks):
        block = plaintext[i * self.block_size : (i + 1) * self.block_size]
        ciphertext.extend(self._xex_encrypt(block, tweaks[i]))
      return bytes(ciphertext)

    # Ciphertext stealing for partial final block
    # In XTS with ciphertext stealing, we use the standard XEX mode
    # but handle the last partial block specially
    tweaks = self._compute_tweak_values(tweak, num_full_blocks + 1)

    # Encrypt all full blocks except the last one
    ciphertext = bytearray()
    for i in range(num_full_blocks - 1):
      block = plaintext[i * self.block_size : (i + 1) * self.block_size]
      ciphertext.extend(self._xex_encrypt(block, tweaks[i]))

    # Get the last full block
    last_full_block = plaintext[
      (num_full_blocks - 1) * self.block_size : num_full_blocks * self.block_size
    ]

    # Get the partial block
    partial_block = plaintext[num_full_blocks * self.block_size :]

    # Encrypt the last full block with tweak M-1 to get CC
    cc = self._xex_encrypt(last_full_block, tweaks[num_full_blocks - 1])

    # XOR partial plaintext with first partial_len bytes of CC to get partial ciphertext
    partial_cipher = bytes([partial_block[i] ^ cc[i] for i in range(partial_len)])

    # Create the stolen block: partial_cipher || cc[partial_len:]
    stolen_block = partial_cipher + cc[partial_len:]

    # Encrypt the stolen block with tweak M
    stolen_cipher = self._xex_encrypt(stolen_block, tweaks[num_full_blocks])

    # Append CC[0:partial_len] as the second-to-last block cipher block
    ciphertext.extend(cc[:partial_len])

    # Append stolen_cipher as the last block
    ciphertext.extend(stolen_cipher)

    return bytes(ciphertext)

  def decrypt(self, ciphertext: bytes, tweak: bytes) -> bytes:
    """Decrypt data using XTS mode."""
    if len(ciphertext) == 0:
      return b""

    # Handle less than one block: use as stream cipher
    # Generate keystream by encrypting zero block, then XOR
    if len(ciphertext) < self.block_size:
      tweaks = self._compute_tweak_values(tweak, 1)
      zero_block = bytes(self.block_size)
      keystream = self._xex_encrypt(zero_block, tweaks[0])
      return bytes([ciphertext[i] ^ keystream[i] for i in range(len(ciphertext))])

    # Handle exact block size - standard XTS decryption
    if len(ciphertext) == self.block_size:
      tweaks = self._compute_tweak_values(tweak, 1)
      return self._xex_decrypt(ciphertext, tweaks[0])

    # Calculate number of full blocks and partial bytes
    num_full_blocks = len(ciphertext) // self.block_size
    partial_len = len(ciphertext) % self.block_size

    if partial_len == 0:
      # No partial block - standard XTS decryption
      tweaks = self._compute_tweak_values(tweak, num_full_blocks)
      plaintext = bytearray()
      for i in range(num_full_blocks):
        block = ciphertext[i * self.block_size : (i + 1) * self.block_size]
        plaintext.extend(self._xex_decrypt(block, tweaks[i]))
      return bytes(plaintext)

    # Ciphertext stealing reversal for partial final block
    tweaks = self._compute_tweak_values(tweak, num_full_blocks + 1)

    # The ciphertext layout for partial blocks is:
    # C_0, C_1, ..., C_{M-2}, CC[0:partial_len], C_stolen
    # where C_stolen = XEX_encrypt(stolen_block, tweak_M)
    # and stolen_block = partial_cipher || CC[partial_len:]
    # and partial_cipher = partial_plaintext XOR CC[0:partial_len]

    # Get all full cipher blocks (except the last partial-like one)
    plaintext = bytearray()
    for i in range(num_full_blocks - 1):
      block = ciphertext[i * self.block_size : (i + 1) * self.block_size]
      plaintext.extend(self._xex_decrypt(block, tweaks[i]))

    # Get CC[0:partial_len] (stored where a full block would be)
    cc_prefix = ciphertext[
      (num_full_blocks - 1) * self.block_size : (num_full_blocks - 1) * self.block_size
      + partial_len
    ]

    # Get C_stolen (the last full cipher block)
    # C_stolen starts after CC[0:partial_len] in the previous "slot"
    stolen_cipher_start = (num_full_blocks - 1) * self.block_size + partial_len
    stolen_cipher = ciphertext[stolen_cipher_start:]

    # Decrypt C_stolen with tweak M to get stolen_block
    stolen_block = self._xex_decrypt(stolen_cipher, tweaks[num_full_blocks])

    # Extract CC[partial_len:] from stolen_block
    cc_tail = stolen_block[partial_len:]

    # Reconstruct CC
    cc = cc_prefix + cc_tail

    # Decrypt CC with tweak M-1 to recover the last full plaintext block
    last_full_plain = self._xex_decrypt(cc, tweaks[num_full_blocks - 1])
    plaintext.extend(last_full_plain)

    # Extract partial_cipher from stolen_block
    partial_cipher = stolen_block[:partial_len]

    # Recover partial plaintext: XOR partial_cipher with CC[0:partial_len]
    partial_plain = bytes([partial_cipher[i] ^ cc[i] for i in range(partial_len)])
    plaintext.extend(partial_plain)

    return bytes(plaintext)


def test_xts_mode():
  """Basic tests for XTS mode."""
  key = b"0123456789abcdef0123456789abcdef"
  tweak = b"\x00" * 16

  xts = XTSMode(key=key)

  # Test basic encryption/decryption
  plaintext = b"Hello, World!1234"
  ciphertext = xts.encrypt(plaintext, tweak)
  decrypted = xts.decrypt(ciphertext, tweak)
  assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

  # Test empty data
  empty = b""
  ciphertext = xts.encrypt(empty, tweak)
  decrypted = xts.decrypt(ciphertext, tweak)
  assert decrypted == empty

  # Test various lengths
  for length in [1, 5, 15, 16, 17, 32, 100]:
    xts = XTSMode(key=key)
    data = b"a" * length
    ciphertext = xts.encrypt(data, tweak)
    assert len(ciphertext) == length, f"Length mismatch for {length} bytes"
    decrypted = xts.decrypt(ciphertext, tweak)
    assert decrypted == data, f"Decrypt failed for {length} bytes"

  print("All XTS mode tests passed!")


if __name__ == "__main__":
  test_xts_mode()
