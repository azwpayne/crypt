# @time    : 2026/3/30
# @name    : ocb.py
# @author  : azwpayne
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : AES-OCB3 (Offset Codebook Mode version 3) — RFC 7253 AEAD.
#           Single-pass authenticated encryption with associated data.
#           Supports AES-128, AES-192, AES-256.

"""AES-OCB3 (RFC 7253) Authenticated Encryption with Associated Data.

OCB3 is a single-pass AEAD mode that provides both confidentiality and
authenticity in a single processing pass over the plaintext.

Security Considerations:
  - NEVER reuse a (key, nonce) pair. Nonce reuse completely breaks security.
  - The nonce does not need to be secret, but must be unique per key.
  - The nonce can be any length up to 15 bytes (120 bits).
  - Tag length is configurable from 1 to 16 bytes.
  - Use a CSPRNG or counter to generate nonces.

Reference:
  RFC 7253 — The OCB Authenticated-Encryption Algorithm
  https://tools.ietf.org/html/rfc7253
"""

from crypt.encrypt.symmetric_encrypt.block_cipher.aes import (
  _encrypt_block,
  _get_key_params,
  key_expansion,
)

BLOCK_SIZE = 16  # AES block size in bytes


def _xor(a: bytes, b: bytes) -> bytes:
  """XOR two equal-length byte strings."""
  return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _double(b: bytes) -> bytes:
  """Multiply a 128-bit value by x in GF(2^128).

  Uses the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
  """
  r = int.from_bytes(b, "big") << 1
  if r >> 128:
    r ^= (1 << 128) | 0x87
  return (r & ((1 << 128) - 1)).to_bytes(16, "big")


def _ntz(n: int) -> int:
  """Number of trailing zeros in the base-2 representation of n."""
  if n == 0:
    return 128
  t = 0
  while (n & 1) == 0:
    t += 1
    n >>= 1
  return t


def _hash_ocb(
  expanded_key: list[int],
  nr: int,
  l_star: bytes,
  l_table: list[bytes],
  aad: bytes,
) -> bytes:
  """OCB3 HASH function for AAD processing (RFC 7253 §4.1)."""
  offset = bytes(BLOCK_SIZE)
  sum_aad = bytes(BLOCK_SIZE)

  aad_blocks = [aad[i : i + BLOCK_SIZE] for i in range(0, len(aad), BLOCK_SIZE)]

  for i, block in enumerate(aad_blocks):
    if len(block) == BLOCK_SIZE:
      offset = _xor(offset, l_table[_ntz(i + 1)])
      encrypted = _encrypt_block(_xor(block, offset), expanded_key, nr)
      sum_aad = _xor(sum_aad, encrypted)
    else:
      offset = _xor(offset, l_star)
      pad_input = block + bytes([0x80]) + bytes(BLOCK_SIZE - len(block) - 1)
      encrypted = _encrypt_block(_xor(pad_input, offset), expanded_key, nr)
      sum_aad = _xor(sum_aad, encrypted)

  return sum_aad


def _derive_offset(
  expanded_key: list[int],
  nr: int,
  nonce: bytes,
  tag_len: int,
) -> bytes:
  """Derive Offset_0 from nonce per RFC 7253 §4.2."""
  # Nonce = num2str(TAGLEN mod 128, 7) || zeros(120-bitlen(N)) || 1 || N
  # TAGLEN is in BITS per RFC 7253
  taglen_bits = tag_len * 8
  nonce_bitlen = len(nonce) * 8
  nonce_int = int.from_bytes(nonce, "big") if nonce else 0

  tag_enc = (taglen_bits % 128) & 0x7F  # 7 bits
  nonce_str_int = (tag_enc << (128 - 7)) | (1 << nonce_bitlen) | nonce_int
  nonce_str = nonce_str_int.to_bytes(16, "big")

  # bottom = str2num(Nonce[123..128]) = last 6 bits
  bottom = nonce_str[15] & 0x3F

  # Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
  ktop_input = bytearray(nonce_str)
  ktop_input[15] &= 0xC0
  ktop = _encrypt_block(bytes(ktop_input), expanded_key, nr)

  # Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
  ktop_first64 = ktop[:8]
  ktop_9_72 = ktop[1:9]
  stretch_ext = bytes(a ^ b for a, b in zip(ktop_first64, ktop_9_72, strict=False))
  stretch = ktop + stretch_ext  # 192 bits = 24 bytes

  # Offset_0 = Stretch[1+bottom..128+bottom] (1-indexed)
  stretch_int = int.from_bytes(stretch, "big")
  offset_0_int = (stretch_int >> (192 - 128 - bottom)) & ((1 << 128) - 1)
  return offset_0_int.to_bytes(16, "big")


def _ocb_encrypt(  # noqa: PLR0913
  expanded_key: list[int],
  nr: int,
  l_star: bytes,
  l_dollar: bytes,
  l_table: list[bytes],
  nonce: bytes,
  tag_len: int,
  plaintext: bytes,
  aad: bytes,
) -> bytes:
  """Core OCB3 encryption (RFC 7253 §4.2)."""
  offset = _derive_offset(expanded_key, nr, nonce, tag_len)

  # --- Process AAD ---
  hash_result = _hash_ocb(expanded_key, nr, l_star, l_table, aad)

  # --- Process plaintext blocks ---
  pt_blocks = [
    plaintext[i : i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)
  ]
  checksum = bytes(BLOCK_SIZE)
  ciphertext = bytearray()

  for i, block in enumerate(pt_blocks):
    if len(block) == BLOCK_SIZE:
      offset = _xor(offset, l_table[_ntz(i + 1)])
      enc_off = _encrypt_block(_xor(block, offset), expanded_key, nr)
      ct_block = _xor(enc_off, offset)
      ciphertext.extend(ct_block)
      checksum = _xor(checksum, block)
    else:
      offset = _xor(offset, l_star)
      pad = _encrypt_block(offset, expanded_key, nr)
      ct_block = bytes(a ^ b for a, b in zip(block, pad, strict=False))
      ciphertext.extend(ct_block)
      padded_pt = block + bytes([0x80]) + bytes(BLOCK_SIZE - len(block) - 1)
      checksum = _xor(checksum, padded_pt)

  # --- Compute tag ---
  tag_input = _xor(_xor(checksum, offset), l_dollar)
  tag = _xor(_encrypt_block(tag_input, expanded_key, nr), hash_result)[:tag_len]

  return bytes(ciphertext) + tag


def _ocb_decrypt(  # noqa: PLR0913
  expanded_key: list[int],
  nr: int,
  l_star: bytes,
  l_dollar: bytes,
  l_table: list[bytes],
  nonce: bytes,
  tag_len: int,
  ciphertext: bytes,
  aad: bytes,
) -> tuple[bytes, bytes]:
  """Core OCB3 decryption (RFC 7253 §4.3)."""
  offset = _derive_offset(expanded_key, nr, nonce, tag_len)

  # --- Process AAD ---
  hash_result = _hash_ocb(expanded_key, nr, l_star, l_table, aad)

  # --- Process ciphertext blocks ---
  ct_blocks = [
    ciphertext[i : i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)
  ]
  plaintext = bytearray()
  checksum = bytes(BLOCK_SIZE)

  for i, block in enumerate(ct_blocks):
    if len(block) == BLOCK_SIZE:
      offset = _xor(offset, l_table[_ntz(i + 1)])
      dec_off = _encrypt_block(_xor(block, offset), expanded_key, nr)
      pt_block = _xor(dec_off, offset)
      plaintext.extend(pt_block)
      checksum = _xor(checksum, pt_block)
    else:
      offset = _xor(offset, l_star)
      pad = _encrypt_block(offset, expanded_key, nr)
      pt_block = bytes(a ^ b for a, b in zip(block, pad, strict=False))
      plaintext.extend(pt_block)
      padded_pt = pt_block + bytes([0x80]) + bytes(BLOCK_SIZE - len(pt_block) - 1)
      checksum = _xor(checksum, padded_pt)

  # --- Compute tag ---
  tag_input = _xor(_xor(checksum, offset), l_dollar)
  tag = _xor(_encrypt_block(tag_input, expanded_key, nr), hash_result)[:tag_len]

  return bytes(plaintext), tag


def _constant_time_compare(a: bytes, b: bytes) -> bool:
  """Compare two byte strings in constant time."""
  if len(a) != len(b):
    return False
  result = 0
  for x, y in zip(a, b, strict=False):
    result |= x ^ y
  return result == 0


def _get_l_table(
  expanded_key: list[int],
  nr: int,
  max_blocks: int,
) -> tuple[bytes, bytes, list[bytes]]:
  """Precompute L_*, L_$, and L(i) values."""
  l_star = _encrypt_block(bytes(BLOCK_SIZE), expanded_key, nr)
  l_dollar = _double(l_star)
  l_zero = _double(l_dollar)

  l_table = [l_zero]
  for _ in range(1, max_blocks.bit_length() + 1):
    l_table.append(_double(l_table[-1]))

  return l_star, l_dollar, l_table


def ocb_encrypt(
  key: bytes,
  nonce: bytes,
  plaintext: bytes,
  aad: bytes = b"",
  tag_len: int = 16,
) -> bytes:
  """Encrypt data using AES-OCB3 (RFC 7253).

  Args:
      key: The encryption key (16, 24, or 32 bytes for AES-128/192/256).
      nonce: The nonce (up to 15 bytes). Must be unique per key.
      plaintext: The data to encrypt.
      aad: Additional authenticated data (authenticated but not encrypted).
      tag_len: Length of authentication tag in bytes (1-16, default 16).

  Returns:
      Ciphertext concatenated with authentication tag.

  Raises:
      ValueError: If key length is invalid, nonce is too long, or tag_len is invalid.
  """
  _nk, nr = _get_key_params(key)
  if len(nonce) > 15:
    msg = f"Nonce must be at most 15 bytes, got {len(nonce)}"
    raise ValueError(msg)
  if tag_len < 1 or tag_len > BLOCK_SIZE:
    msg = f"tag_len must be between 1 and {BLOCK_SIZE}, got {tag_len}"
    raise ValueError(msg)

  expanded_key = key_expansion(key)
  total_blocks = max(
    (len(plaintext) + BLOCK_SIZE - 1) // BLOCK_SIZE,
    (len(aad) + BLOCK_SIZE - 1) // BLOCK_SIZE,
    1,
  )
  l_star, l_dollar, l_table = _get_l_table(expanded_key, nr, total_blocks)

  return _ocb_encrypt(
    expanded_key,
    nr,
    l_star,
    l_dollar,
    l_table,
    nonce,
    tag_len,
    plaintext,
    aad,
  )


def ocb_decrypt(
  key: bytes,
  nonce: bytes,
  ciphertext_with_tag: bytes,
  aad: bytes = b"",
  tag_len: int = 16,
) -> bytes:
  """Decrypt data using AES-OCB3 (RFC 7253).

  Args:
      key: The encryption key (16, 24, or 32 bytes for AES-128/192/256).
      nonce: The nonce used during encryption (up to 15 bytes).
      ciphertext_with_tag: The ciphertext concatenated with authentication tag.
      aad: Additional authenticated data (must match encryption value).
      tag_len: Length of authentication tag in bytes (1-16, default 16).

  Returns:
      The decrypted plaintext if authentication succeeds.

  Raises:
      ValueError: If inputs are invalid or authentication fails.
  """
  _nk, nr = _get_key_params(key)
  if len(nonce) > 15:
    msg = f"Nonce must be at most 15 bytes, got {len(nonce)}"
    raise ValueError(msg)
  if tag_len < 1 or tag_len > BLOCK_SIZE:
    msg = f"tag_len must be between 1 and {BLOCK_SIZE}, got {tag_len}"
    raise ValueError(msg)
  if len(ciphertext_with_tag) < tag_len:
    msg = f"Ciphertext too short: need at least {tag_len} bytes for tag"
    raise ValueError(msg)

  ciphertext = ciphertext_with_tag[:-tag_len]
  received_tag = ciphertext_with_tag[-tag_len:]

  expanded_key = key_expansion(key)
  total_blocks = max(
    (len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE,
    (len(aad) + BLOCK_SIZE - 1) // BLOCK_SIZE,
    1,
  )
  l_star, l_dollar, l_table = _get_l_table(expanded_key, nr, total_blocks)

  plaintext, computed_tag = _ocb_decrypt(
    expanded_key,
    nr,
    l_star,
    l_dollar,
    l_table,
    nonce,
    tag_len,
    ciphertext,
    aad,
  )

  if not _constant_time_compare(received_tag, computed_tag):
    msg = "Authentication failed: invalid tag"
    raise ValueError(msg)

  return plaintext


if __name__ == "__main__":
  # RFC 7253 Appendix A test vector #1 (AES-128, empty plaintext)
  key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
  nonce = bytes.fromhex("000102030405060708090a0b0c")
  ct = ocb_encrypt(key, nonce, b"", b"", tag_len=16)
  expected = bytes.fromhex("197b9c3c441d3c83eafb2bea3f52b4c7")
  print(f"Tag:   {ct.hex()}")
  print(f"Exp:   {expected.hex()}")
  assert ct == expected, f"Mismatch: {ct.hex()} != {expected.hex()}"
  print("Test vector #1 passed!")
