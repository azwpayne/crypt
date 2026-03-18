"""EAX (Encrypt-then-Authenticate-then-Translate) mode implementation.

EAX is an authenticated encryption mode that combines CTR mode for encryption
with CMAC (Cipher-based MAC) for authentication. It provides both confidentiality
and authenticity.

EAX mode is a two-pass AEAD (Authenticated Encryption with Associated Data) scheme:
1. First pass: Compute CMAC over the associated data, nonce, and ciphertext
2. Second pass: Encrypt/decrypt using CTR mode

Security properties:
- Confidentiality: Provided by CTR mode encryption
- Authenticity: Provided by CMAC authentication tag
- Nonce-misuse resistance: EAX is not nonce-misuse resistant; reusing a nonce
  with the same key compromises security

WARNING: Never reuse a (key, nonce) pair - this will compromise security.
"""

from collections.abc import Callable
from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
  _encrypt_block,
  _get_key_params,
  key_expansion,
)


class EAXMode:
  """EAX (Encrypt-then-Authenticate-then-Translate) authenticated encryption mode.

  EAX mode provides both confidentiality and authenticity by combining CTR mode
  encryption with CMAC authentication. It supports associated data (AEAD) that
  is authenticated but not encrypted.

  This mode provides:
  - Authenticated encryption: Both confidentiality and integrity protection
  - Associated data support: Authenticate additional data without encrypting it
  - Single key: Uses the same key for both encryption and authentication
  - Parallelizable: CTR encryption can be parallelized

  Attributes:
      block_size: The block size in bytes (16 for AES).
      key: The encryption key.
      expanded_key: The expanded key schedule.
      nr: Number of rounds.
      tag_length: Length of the authentication tag in bytes.

  Example:
      >>> eax = EAXMode(key=b'0123456789abcdef', tag_length=16)
      >>> nonce = b'unique_nonce_16b'  # 16 bytes for AES
      >>> plaintext = b"Hello, World!"
      >>> aad = b"authenticated header"
      >>> ciphertext, tag = eax.encrypt(plaintext, nonce, aad)
      >>> decrypted = eax.decrypt(ciphertext, nonce, tag, aad)
      >>> assert decrypted == plaintext
  """

  # ruff: noqa: PLR0913
  def __init__(
    self,
    encrypt_func: Callable[[bytes], bytes] | None = None,
    decrypt_func: Callable[[bytes], bytes] | None = None,  # noqa: ARG002
    block_size: int = 16,
    key: bytes | None = None,
    expanded_key: list[int] | None = None,
    nr: int | None = None,
    tag_length: int = 16,
  ):
    """Initialize EAX mode.

    Args:
        encrypt_func: Optional external encrypt function.
        decrypt_func: Optional external decrypt function (not used in EAX).
        block_size: The block size in bytes (default 16 for AES).
        key: The encryption key (required if using AES).
        expanded_key: Pre-computed expanded key (optional).
        nr: Number of rounds (optional, derived from key if not provided).
        tag_length: Length of authentication tag in bytes (default 16, max 16).

    Raises:
        ValueError: If key is not provided and no external functions are given.
        ValueError: If tag_length is invalid.
    """
    if tag_length < 1 or tag_length > block_size:
      msg = f"tag_length must be between 1 and {block_size}"
      raise ValueError(msg)

    self.block_size = block_size
    self._encrypt_func = encrypt_func
    self.tag_length = tag_length

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

    # Precompute CMAC subkeys for efficiency
    self._L = self._encrypt_block(bytes(block_size))
    self._K1 = self._double_gf128(self._L)
    self._K2 = self._double_gf128(self._K1)

  def _encrypt_block(self, block: bytes) -> bytes:
    """Encrypt a single block using the underlying block cipher.

    Args:
        block: The block to encrypt (must be block_size bytes).

    Returns:
        The encrypted block.
    """
    if self._encrypt_func is not None:
      return self._encrypt_func(block)
    return _encrypt_block(block, self.expanded_key, self.nr)

  def _double_gf128(self, x: bytes) -> bytes:
    """Double a value in GF(2^128) for CMAC subkey derivation.

    This implements the doubling operation in the finite field GF(2^128)
    with the irreducible polynomial x^128 + x^7 + x^2 + x + 1.

    Args:
        x: The input value (16 bytes).

    Returns:
        The doubled value (16 bytes).
    """
    # Convert to integer for bit manipulation
    x_int = int.from_bytes(x, "big")

    # Shift left by 1 (multiply by x in GF(2^128))
    result = x_int << 1

    # If the MSB was 1, XOR with the reduction polynomial
    # The polynomial is x^128 + x^7 + x^2 + x + 1
    # We only need the lower 128 bits, so XOR with 0x87 if MSB was 1
    if x_int & (1 << 127):
      result ^= 0x87

    return (result & ((1 << 128) - 1)).to_bytes(16, "big")

  def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
    """XOR two byte strings together.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        The XOR of the two byte strings (length of shorter input).
    """
    return bytes(x ^ y for x, y in zip(a, b, strict=False))

  def _cmac(self, data: bytes) -> bytes:
    """Compute CMAC (Cipher-based Message Authentication Code).

    CMAC is a block cipher-based MAC algorithm defined in NIST SP 800-38B.

    Args:
        data: The data to authenticate.

    Returns:
        The CMAC value (full block size).
    """
    n = (len(data) + self.block_size - 1) // self.block_size

    if n == 0:
      # Empty message case
      pad = bytes([0x80]) + bytes(self.block_size - 1)
      block = self._xor_bytes(pad, self._K2)
      return self._encrypt_block(block)

    # Process complete blocks
    mac = bytes(self.block_size)
    for i in range(n - 1):
      block = data[i * self.block_size : (i + 1) * self.block_size]
      mac = self._encrypt_block(self._xor_bytes(mac, block))

    # Process final block
    last_block_start = (n - 1) * self.block_size
    last_block = data[last_block_start:]

    if len(last_block) == self.block_size:
      # Complete block: XOR with K1
      final_block = self._xor_bytes(last_block, self._K1)
    else:
      # Incomplete block: pad and XOR with K2
      pad_len = self.block_size - len(last_block) - 1
      padded = last_block + bytes([0x80]) + bytes(pad_len)
      final_block = self._xor_bytes(padded, self._K2)

    return self._encrypt_block(self._xor_bytes(mac, final_block))

  def _ctr_crypt(self, data: bytes, nonce: bytes) -> bytes:
    """Encrypt/decrypt data using CTR mode.

    EAX uses a modified CTR mode where the counter is formed by XORing
    the nonce with a block index.

    Args:
        data: The data to encrypt/decrypt.
        nonce: The nonce (must be block_size bytes).

    Returns:
        The encrypted/decrypted data.
    """
    result = bytearray()

    for i in range(0, len(data), self.block_size):
      # Create counter block: nonce XOR block_index
      block_index = i // self.block_size
      counter_bytes = block_index.to_bytes(self.block_size, "big")
      counter_block = self._xor_bytes(nonce, counter_bytes)

      # Encrypt counter block to get keystream
      keystream = self._encrypt_block(counter_block)

      # XOR with data block
      block = data[i : i + self.block_size]
      xored = bytes([block[j] ^ keystream[j] for j in range(len(block))])
      result.extend(xored)

    return bytes(result)

  def encrypt(
    self,
    plaintext: bytes,
    nonce: bytes,
    associated_data: bytes = b"",
    *,
    aad: bytes | None = None,
  ) -> tuple[bytes, bytes]:
    """Encrypt data and generate authentication tag using EAX mode.

    Args:
        plaintext: The data to encrypt.
        nonce: The nonce (must be block_size bytes). Must be unique per key.
        associated_data: Additional data to authenticate but not encrypt.
        aad: Alias for associated_data (for compatibility with pycryptodome API).

    Returns:
        Tuple of (ciphertext, authentication_tag).

    Raises:
        ValueError: If nonce length is not equal to block_size.

    WARNING:
        Never reuse a nonce with the same key. Nonce reuse completely
        breaks the security of EAX mode.
    """
    # Use aad if provided, otherwise fall back to associated_data
    if aad is not None:
      associated_data = aad
    if len(nonce) != self.block_size:
      msg = f"Nonce must be {self.block_size} bytes, got {len(nonce)}"
      raise ValueError(msg)

    # Derive authentication nonce (nonce with tag = 0)
    auth_nonce = self._xor_bytes(nonce, bytes(self.block_size))

    # Derive encryption nonce (nonce with tag = 1)
    enc_nonce = self._xor_bytes(nonce, bytes(self.block_size - 1) + bytes([1]))

    # Compute header CMAC (associated data)
    if associated_data:
      # Tag = 1 for header
      header_tag = bytes(self.block_size - 1) + bytes([1])
      header_nonce = self._xor_bytes(nonce, header_tag)
      header_cmac = self._cmac(header_nonce + associated_data)
    else:
      header_cmac = bytes(self.block_size)

    # Encrypt plaintext using CTR mode
    ciphertext = self._ctr_crypt(plaintext, enc_nonce)

    # Compute message CMAC (ciphertext)
    # Tag = 2 for message
    msg_tag = bytes(self.block_size - 1) + bytes([2])
    msg_nonce = self._xor_bytes(nonce, msg_tag)
    msg_cmac = self._cmac(msg_nonce + ciphertext)

    # Compute final tag: CMAC(nonce) XOR header_cmac XOR msg_cmac
    nonce_cmac = self._cmac(auth_nonce)
    full_tag = self._xor_bytes(self._xor_bytes(nonce_cmac, header_cmac), msg_cmac)
    tag = full_tag[: self.tag_length]

    return ciphertext, tag

  def decrypt(
    self,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    associated_data: bytes = b"",
    *,
    aad: bytes | None = None,
  ) -> bytes:
    """Decrypt data and verify authentication tag using EAX mode.

    Args:
        ciphertext: The data to decrypt.
        nonce: The nonce (must be block_size bytes).
        tag: The authentication tag to verify.
        associated_data: Additional authenticated data.
        aad: Alias for associated_data (for compatibility with pycryptodome API).

    Returns:
        The decrypted plaintext if authentication succeeds.

    Raises:
        ValueError: If nonce length is invalid or authentication fails.

    WARNING:
        Never reuse a nonce with the same key. Nonce reuse completely
        breaks the security of EAX mode.
    """
    # Use aad if provided, otherwise fall back to associated_data
    if aad is not None:
      associated_data = aad
    if len(nonce) != self.block_size:
      msg = f"Nonce must be {self.block_size} bytes, got {len(nonce)}"
      raise ValueError(msg)

    if len(tag) != self.tag_length:
      msg = f"Tag must be {self.tag_length} bytes, got {len(tag)}"
      raise ValueError(msg)

    # Derive authentication nonce (nonce with tag = 0)
    auth_nonce = self._xor_bytes(nonce, bytes(self.block_size))

    # Derive encryption nonce (nonce with tag = 1)
    enc_nonce = self._xor_bytes(nonce, bytes(self.block_size - 1) + bytes([1]))

    # Compute header CMAC (associated data)
    if associated_data:
      # Tag = 1 for header
      header_tag = bytes(self.block_size - 1) + bytes([1])
      header_nonce = self._xor_bytes(nonce, header_tag)
      header_cmac = self._cmac(header_nonce + associated_data)
    else:
      header_cmac = bytes(self.block_size)

    # Compute message CMAC (ciphertext)
    # Tag = 2 for message
    msg_tag = bytes(self.block_size - 1) + bytes([2])
    msg_nonce = self._xor_bytes(nonce, msg_tag)
    msg_cmac = self._cmac(msg_nonce + ciphertext)

    # Compute expected tag: CMAC(nonce) XOR header_cmac XOR msg_cmac
    nonce_cmac = self._cmac(auth_nonce)
    expected_full_tag = self._xor_bytes(
      self._xor_bytes(nonce_cmac, header_cmac), msg_cmac
    )
    expected_tag = expected_full_tag[: self.tag_length]

    # Verify tag (constant-time comparison)
    if not self._constant_time_compare(tag, expected_tag):
      msg = "Authentication failed: invalid tag"
      raise ValueError(msg)

    # Decrypt ciphertext using CTR mode
    return self._ctr_crypt(ciphertext, enc_nonce)

  def verify(
    self, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b""
  ) -> bool:
    """Verify the authentication tag without decrypting.

    Args:
        ciphertext: The ciphertext to verify.
        nonce: The nonce used for encryption.
        tag: The authentication tag to verify.
        associated_data: Additional authenticated data.

    Returns:
        True if the tag is valid, False otherwise.
    """
    try:
      self.decrypt(ciphertext, nonce, tag, associated_data)
    except ValueError:
      return False
    else:
      return True

  def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.

    This prevents timing attacks that could leak information about
    the expected tag value.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if the byte strings are equal, False otherwise.
    """
    if len(a) != len(b):
      return False
    result = 0
    for x, y in zip(a, b, strict=False):
      result |= x ^ y
    return result == 0


def test_eax_mode():
  """Basic tests for EAX mode."""
  key = b"0123456789abcdef"
  nonce = b"1234567890123456"  # 16 bytes for AES

  eax = EAXMode(key=key)

  # Test basic encryption/decryption
  plaintext = b"Hello, World!"
  ciphertext, tag = eax.encrypt(plaintext, nonce)
  decrypted = eax.decrypt(ciphertext, nonce, tag)
  assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

  # Test empty data
  empty = b""
  ciphertext, tag = eax.encrypt(empty, nonce)
  decrypted = eax.decrypt(ciphertext, nonce, tag)
  assert decrypted == empty

  # Test with associated data
  aad = b"authenticated header"
  ciphertext, tag = eax.encrypt(plaintext, nonce, aad)
  decrypted = eax.decrypt(ciphertext, nonce, tag, aad)
  assert decrypted == plaintext

  # Test wrong AAD fails
  try:
    eax.decrypt(ciphertext, nonce, tag, b"wrong_aad")
    msg = "Should have raised ValueError for wrong AAD"
    raise AssertionError(msg)
  except ValueError:
    pass  # Expected

  # Test wrong tag fails
  try:
    wrong_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
    eax.decrypt(ciphertext, nonce, wrong_tag, aad)
    msg = "Should have raised ValueError for wrong tag"
    raise AssertionError(msg)
  except ValueError:
    pass  # Expected

  # Test tampered ciphertext fails
  try:
    tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
    eax.decrypt(tampered, nonce, tag, aad)
    msg = "Should have raised ValueError for tampered ciphertext"
    raise AssertionError(msg)
  except ValueError:
    pass  # Expected

  print("All EAX mode tests passed!")


if __name__ == "__main__":
  test_eax_mode()
