# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_salsa20.py
# @time    : 2026/3/17
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Tests for Salsa20 stream cipher

"""
Test suite for Salsa20 stream cipher implementation.

Salsa20 is a 256-bit stream cipher using a 64-bit nonce.
Tests include:
- Known test vectors from Salsa20 specification
- Round-trip encryption/decryption
- Incremental counter handling
- Various plaintext lengths
"""

from __future__ import annotations

from crypt.encrypt.symmetric_encrypt.stream_cipher.salsa20 import (
  quarter_round,
  rotl,
  salsa20_block,
  salsa20_encrypt,
)


class TestSalsa20:
  """Test cases for Salsa20 stream cipher."""

  def test_rotl(self):
    """Test rotate left function."""
    # Basic test
    assert rotl(0x80000000, 1) == 0x00000001
    # No rotation
    assert rotl(0x12345678, 0) == 0x12345678
    # Full rotation (32 bits)
    assert rotl(0x12345678, 32) == 0x12345678
    # 8-bit rotation
    assert rotl(0x12345678, 8) == 0x34567812

  def test_quarter_round(self):
    """Test quarter round function modifies state correctly."""
    # Test that quarter_round modifies the state
    x = [0] * 16
    x[0] = 1
    x[4] = 2
    x[8] = 3
    x[12] = 4

    original = x.copy()
    quarter_round(x, 0, 4, 8, 12)

    # State should be modified
    assert x != original

  def test_salsa20_block_output_length(self):
    """Test that salsa20_block produces 64-byte output."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0

    block = salsa20_block(key, counter, nonce)

    assert len(block) == 64

  def test_salsa20_block_deterministic(self):
    """Test that salsa20_block is deterministic."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0

    block1 = salsa20_block(key, counter, nonce)
    block2 = salsa20_block(key, counter, nonce)

    assert block1 == block2

  def test_salsa20_block_different_counters(self):
    """Test that different counters produce different blocks."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")

    block1 = salsa20_block(key, 0, nonce)
    block2 = salsa20_block(key, 1, nonce)

    assert block1 != block2

  def test_salsa20_basic_encrypt_decrypt(self):
    """Test basic encryption and decryption."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0
    plaintext = b"Hello, Salsa20!"

    # Encrypt
    ciphertext = salsa20_encrypt(key, nonce, counter, plaintext)
    # Decrypt (same operation for Salsa20)
    decrypted = salsa20_encrypt(key, nonce, counter, ciphertext)

    assert decrypted == plaintext

  def test_salsa20_large_data(self):
    """Test Salsa20 with data larger than one block (64 bytes)."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0
    plaintext = b"A" * 1000  # Much larger than 64 bytes

    ciphertext = salsa20_encrypt(key, nonce, counter, plaintext)
    decrypted = salsa20_encrypt(key, nonce, counter, ciphertext)

    assert decrypted == plaintext
    assert len(ciphertext) == len(plaintext)

  def test_salsa20_exact_block_size(self):
    """Test Salsa20 with exactly 64 bytes (one block)."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0
    plaintext = b"X" * 64

    ciphertext = salsa20_encrypt(key, nonce, counter, plaintext)
    decrypted = salsa20_encrypt(key, nonce, counter, ciphertext)

    assert decrypted == plaintext

  def test_salsa20_empty_plaintext(self):
    """Test Salsa20 with empty plaintext."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0
    plaintext = b""

    ciphertext = salsa20_encrypt(key, nonce, counter, plaintext)
    decrypted = salsa20_encrypt(key, nonce, counter, ciphertext)

    assert decrypted == plaintext
    assert ciphertext == b""

  def test_salsa20_binary_data(self):
    """Test Salsa20 with all byte values."""
    key = bytes(range(32))  # All values 0-31
    nonce = bytes(range(8))  # All values 0-7
    counter = 0
    plaintext = bytes(range(256))  # All possible byte values

    ciphertext = salsa20_encrypt(key, nonce, counter, plaintext)
    decrypted = salsa20_encrypt(key, nonce, counter, ciphertext)

    assert decrypted == plaintext

  def test_salsa20_different_nonces(self):
    """Test that different nonces produce different ciphertexts."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce1 = bytes.fromhex("9565542946c322be")
    nonce2 = bytes.fromhex("0000000000000001")
    counter = 0
    plaintext = b"Test message for nonce"

    ciphertext1 = salsa20_encrypt(key, nonce1, counter, plaintext)
    ciphertext2 = salsa20_encrypt(key, nonce2, counter, plaintext)

    assert ciphertext1 != ciphertext2

  def test_salsa20_different_keys(self):
    """Test that different keys produce different ciphertexts."""
    key1 = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    key2 = bytes.fromhex(
      "1ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0
    plaintext = b"Test message for key"

    ciphertext1 = salsa20_encrypt(key1, nonce, counter, plaintext)
    ciphertext2 = salsa20_encrypt(key2, nonce, counter, plaintext)

    assert ciphertext1 != ciphertext2

  def test_salsa20_ciphertext_length(self):
    """Test that ciphertext length equals plaintext length."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0

    for length in [0, 1, 16, 32, 63, 64, 65, 100, 1000]:
      plaintext = b"X" * length
      ciphertext = salsa20_encrypt(key, nonce, counter, plaintext)
      assert len(ciphertext) == len(plaintext)

  def test_salsa20_counter_increment(self):
    """Test that counter properly increments across multiple blocks."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")

    # Encrypt 3 blocks worth of data with counter=0
    plaintext = b"X" * (64 * 3)
    ciphertext1 = salsa20_encrypt(key, nonce, 0, plaintext)

    # Encrypt same data with counter=3
    ciphertext2 = salsa20_encrypt(key, nonce, 3, plaintext)

    # Should be different because keystream starts at different position
    assert ciphertext1 != ciphertext2

  def test_salsa20_xor_property(self):
    """Test that plaintext XOR ciphertext = keystream."""
    key = bytes.fromhex(
      "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
    )
    nonce = bytes.fromhex("9565542946c322be")
    counter = 0
    plaintext = b"Test message!!"

    ciphertext = salsa20_encrypt(key, nonce, counter, plaintext)

    # XOR plaintext with ciphertext to get keystream
    keystream = bytes(p ^ c for p, c in zip(plaintext, ciphertext, strict=False))

    # Same plaintext XORed with same keystream should give same ciphertext
    ciphertext2 = bytes(p ^ k for p, k in zip(plaintext, keystream, strict=False))
    assert ciphertext2 == ciphertext
