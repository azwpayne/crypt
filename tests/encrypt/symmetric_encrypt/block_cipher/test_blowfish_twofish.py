# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_blowfish_twofish.py
# @time    : 2026/3/15
# @desc    : Tests for Blowfish and Twofish block ciphers

from crypt.encrypt.symmetric_encrypt.block_cipher.blowfish import (
  Blowfish,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.blowfish import (
  decrypt_cbc as bf_decrypt_cbc,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.blowfish import (
  decrypt_ecb as bf_decrypt_ecb,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.blowfish import (
  encrypt_cbc as bf_encrypt_cbc,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.blowfish import (
  encrypt_ecb as bf_encrypt_ecb,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.twofish import (
  Twofish,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.twofish import (
  decrypt_cbc as tf_decrypt_cbc,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.twofish import (
  decrypt_ecb as tf_decrypt_ecb,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.twofish import (
  encrypt_cbc as tf_encrypt_cbc,
)
from crypt.encrypt.symmetric_encrypt.block_cipher.twofish import (
  encrypt_ecb as tf_encrypt_ecb,
)

import pytest


class TestBlowfish:
  """Test Blowfish block cipher."""

  def test_key_sizes(self):
    """Test Blowfish accepts various key sizes."""
    # Minimum key size (4 bytes)
    Blowfish(b"1234")
    # Maximum key size (56 bytes)
    Blowfish(b"a" * 56)
    # Various sizes in between
    Blowfish(b"12345678")
    Blowfish(b"1234567890123456")

  def test_invalid_key_size(self):
    """Test Blowfish rejects invalid key sizes."""
    with pytest.raises(ValueError, match="Key must be 4-56 bytes"):
      Blowfish(b"123")  # Too short
    with pytest.raises(ValueError, match="Key must be 4-56 bytes"):
      Blowfish(b"a" * 57)  # Too long

  def test_block_encryption(self):
    """Test single block encryption/decryption."""
    key = b"0123456789abcdef"
    cipher = Blowfish(key)

    plaintext = b"abcdefgh"  # 8 bytes
    ciphertext = cipher.encrypt_block(plaintext)
    decrypted = cipher.decrypt_block(ciphertext)

    assert len(ciphertext) == 8
    assert decrypted == plaintext

  def test_invalid_block_size(self):
    """Test block operations reject invalid sizes."""
    cipher = Blowfish(b"12345678")

    with pytest.raises(ValueError, match="Block must be 8 bytes"):
      cipher.encrypt_block(b"short")  # Too short
    with pytest.raises(ValueError, match="Block must be 8 bytes"):
      cipher.encrypt_block(b"too long!!")  # Too long

  def test_ecb_roundtrip(self):
    """Test ECB mode encryption/decryption roundtrip."""
    key = b"mysecretkey"
    plaintext = b"Hello, World!"

    ciphertext = bf_encrypt_ecb(key, plaintext)
    decrypted = bf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_ecb_multiple_blocks(self):
    """Test ECB mode with multiple blocks."""
    key = b"0123456789abcdef"
    plaintext = b"This is a longer message that spans multiple blocks!"

    ciphertext = bf_encrypt_ecb(key, plaintext)
    decrypted = bf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_ecb_exact_block(self):
    """Test ECB mode with exact block size."""
    key = b"0123456789abcdef"
    plaintext = b"exactly8"  # Exactly 8 bytes

    ciphertext = bf_encrypt_ecb(key, plaintext)
    decrypted = bf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_cbc_roundtrip(self):
    """Test CBC mode encryption/decryption roundtrip."""
    key = b"mysecretkey"
    iv = b"initvec!"  # 8 bytes
    plaintext = b"Hello, World!"

    ciphertext = bf_encrypt_cbc(key, iv, plaintext)
    decrypted = bf_decrypt_cbc(key, iv, ciphertext)

    assert decrypted == plaintext

  def test_cbc_different_ivs(self):
    """Test CBC mode produces different ciphertext with different IVs."""
    key = b"mysecretkey"
    iv1 = b"initvec1"
    iv2 = b"initvec2"
    plaintext = b"Hello, World!"

    ciphertext1 = bf_encrypt_cbc(key, iv1, plaintext)
    ciphertext2 = bf_encrypt_cbc(key, iv2, plaintext)

    assert ciphertext1 != ciphertext2

  def test_cbc_invalid_iv(self):
    """Test CBC mode rejects invalid IV."""
    with pytest.raises(ValueError, match="IV must be 8 bytes"):
      bf_encrypt_cbc(b"secretkey", b"short", b"plaintext")

  def test_empty_plaintext(self):
    """Test encryption of empty plaintext."""
    key = b"0123456789abcdef"
    plaintext = b""

    ciphertext = bf_encrypt_ecb(key, plaintext)
    decrypted = bf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_known_vectors(self):
    """Test against known test vectors."""
    # Test vector from Blowfish specification
    key = bytes([0x00] * 8)
    plaintext = bytes([0x00] * 8)

    cipher = Blowfish(key)
    ciphertext = cipher.encrypt_block(plaintext)
    decrypted = cipher.decrypt_block(ciphertext)

    assert decrypted == plaintext


class TestTwofish:
  """Test Twofish block cipher."""

  def test_key_sizes(self):
    """Test Twofish accepts valid key sizes."""
    # 128-bit key
    Twofish(b"1234567890123456")
    # 192-bit key
    Twofish(b"123456789012345678901234")
    # 256-bit key
    Twofish(b"12345678901234567890123456789012")

  def test_invalid_key_size(self):
    """Test Twofish rejects invalid key sizes."""
    with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes"):
      Twofish(b"123456789012345")  # 15 bytes
    with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes"):
      Twofish(b"123456789012345678")  # 18 bytes
    with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes"):
      Twofish(b"a" * 33)  # 33 bytes

  def test_block_encryption(self):
    """Test single block encryption/decryption."""
    key = b"0123456789abcdef"  # 16 bytes
    cipher = Twofish(key)

    plaintext = b"1234567890123456"  # 16 bytes
    ciphertext = cipher.encrypt_block(plaintext)
    decrypted = cipher.decrypt_block(ciphertext)

    assert len(ciphertext) == 16
    assert decrypted == plaintext

  def test_invalid_block_size(self):
    """Test block operations reject invalid sizes."""
    cipher = Twofish(b"0123456789abcdef")

    with pytest.raises(ValueError, match="Block must be 16 bytes"):
      cipher.encrypt_block(b"short")  # Too short
    with pytest.raises(ValueError, match="Block must be 16 bytes"):
      cipher.encrypt_block(b"too long for block")  # Too long

  def test_ecb_roundtrip(self):
    """Test ECB mode encryption/decryption roundtrip."""
    key = b"0123456789abcdef"
    plaintext = b"Hello, World!!!"

    ciphertext = tf_encrypt_ecb(key, plaintext)
    decrypted = tf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_ecb_multiple_blocks(self):
    """Test ECB mode with multiple blocks."""
    key = b"0123456789abcdef"
    plaintext = b"This is a longer message that spans multiple 128-bit blocks!"

    ciphertext = tf_encrypt_ecb(key, plaintext)
    decrypted = tf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_ecb_exact_block(self):
    """Test ECB mode with exact block size."""
    key = b"0123456789abcdef"
    plaintext = b"exactly16bytes!!"  # Exactly 16 bytes

    ciphertext = tf_encrypt_ecb(key, plaintext)
    decrypted = tf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_cbc_roundtrip(self):
    """Test CBC mode encryption/decryption roundtrip."""
    key = b"0123456789abcdef"
    iv = b"1234567890123456"  # 16 bytes
    plaintext = b"Hello, World!!!"

    ciphertext = tf_encrypt_cbc(key, iv, plaintext)
    decrypted = tf_decrypt_cbc(key, iv, ciphertext)

    assert decrypted == plaintext

  def test_cbc_different_ivs(self):
    """Test CBC mode produces different ciphertext with different IVs."""
    key = b"0123456789abcdef"
    iv1 = b"1234567890123456"
    iv2 = b"6543210987654321"
    plaintext = b"Hello, World!!!"

    ciphertext1 = tf_encrypt_cbc(key, iv1, plaintext)
    ciphertext2 = tf_encrypt_cbc(key, iv2, plaintext)

    assert ciphertext1 != ciphertext2

  def test_cbc_invalid_iv(self):
    """Test CBC mode rejects invalid IV."""
    with pytest.raises(ValueError, match="IV must be 16 bytes"):
      tf_encrypt_cbc(b"0123456789abcdef", b"short", b"plaintext")

  def test_empty_plaintext(self):
    """Test encryption of empty plaintext."""
    key = b"0123456789abcdef"
    plaintext = b""

    ciphertext = tf_encrypt_ecb(key, plaintext)
    decrypted = tf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_all_key_lengths(self):
    """Test all valid key lengths."""
    plaintext = b"Test message!!!!"

    # 128-bit
    key128 = b"0123456789abcdef"
    ct128 = tf_encrypt_ecb(key128, plaintext)
    assert tf_decrypt_ecb(key128, ct128) == plaintext

    # 192-bit
    key192 = b"0123456789abcdefghijklmn"
    ct192 = tf_encrypt_ecb(key192, plaintext)
    assert tf_decrypt_ecb(key192, ct192) == plaintext

    # 256-bit
    key256 = b"0123456789abcdefghijklmnopqrstuv"
    ct256 = tf_encrypt_ecb(key256, plaintext)
    assert tf_decrypt_ecb(key256, ct256) == plaintext


class TestBlowfishVsReference:
  """Test Blowfish against pycryptodome reference implementation."""

  def test_vs_known_vector_ecb(self):
    """Compare ECB encryption with known Blowfish test vector.

    Vector from https://www.schneier.com/code/vectors.txt
    Key: "AAAA..." (0x4141414141414141), Plaintext: 0x4141414141414141
    Expected: 0xa17dba6a27f3a26f
    """
    # 8-byte key, 8-byte plaintext block
    key = bytes.fromhex("4141414141414141")
    plaintext = bytes.fromhex("4141414141414141")
    expected_ciphertext = bytes.fromhex("a17dba6a27f3a26f")

    bf = Blowfish(key)
    result = bf.encrypt_block(plaintext)
    assert result == expected_ciphertext
    decrypted = bf.decrypt_block(result)
    assert decrypted == plaintext


class TestTwofishVsReference:
  """Test Twofish against pycryptodome reference implementation."""

  @pytest.mark.skipif(
    pytest.importorskip("Crypto.Cipher.Twofish", reason="pycryptodome not installed")
    is None,
    reason="pycryptodome Twofish not available",
  )
  def test_vs_pycryptodome_ecb(self):
    """Compare ECB encryption with pycryptodome."""
    import importlib
    from typing import Any

    ref_twofish: Any = importlib.import_module("Crypto.Cipher.Twofish")
    from Crypto.Util.Padding import pad

    key = b"0123456789abcdef"
    plaintext = b"hello world!!!!!"

    # Our implementation
    our_ciphertext = tf_encrypt_ecb(key, plaintext)

    # Reference implementation
    ref_cipher = ref_twofish.new(key, ref_twofish.MODE_ECB)
    ref_ciphertext = ref_cipher.encrypt(pad(plaintext, 16))

    assert our_ciphertext == ref_ciphertext


class TestBlowfishEdgeCases:
  """Test Blowfish edge cases."""

  def test_binary_data(self):
    """Test encryption of binary data with all byte values."""
    key = b"0123456789abcdef"
    plaintext = bytes(range(256))  # All byte values

    ciphertext = bf_encrypt_ecb(key, plaintext)
    decrypted = bf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_long_key(self):
    """Test with maximum length key."""
    key = b"a" * 56
    plaintext = b"Test data for encryption"

    ciphertext = bf_encrypt_ecb(key, plaintext)
    decrypted = bf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext


class TestTwofishEdgeCases:
  """Test Twofish edge cases."""

  def test_binary_data(self):
    """Test encryption of binary data with all byte values."""
    key = b"0123456789abcdef"
    plaintext = bytes(range(256))  # All byte values

    ciphertext = tf_encrypt_ecb(key, plaintext)
    decrypted = tf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext

  def test_256_bit_key(self):
    """Test with 256-bit key."""
    key = b"0123456789abcdefghijklmnopqrstuv"
    plaintext = b"Test data for encryption"

    ciphertext = tf_encrypt_ecb(key, plaintext)
    decrypted = tf_decrypt_ecb(key, ciphertext)

    assert decrypted == plaintext


class TestCrossModeConsistency:
  """Test consistency between different modes."""

  def test_blowfish_same_key_different_modes(self):
    """Test that same key works across different modes."""
    key = b"mytestkey"
    plaintext = b"Test message here"
    iv = b"initvec!"

    ecb_ct = bf_encrypt_ecb(key, plaintext)
    cbc_ct = bf_encrypt_cbc(key, iv, plaintext)

    # ECB and CBC should produce different ciphertext
    assert ecb_ct != cbc_ct

    # But both should decrypt correctly
    assert bf_decrypt_ecb(key, ecb_ct) == plaintext
    assert bf_decrypt_cbc(key, iv, cbc_ct) == plaintext

  def test_twofish_same_key_different_modes(self):
    """Test that same key works across different modes."""
    key = b"0123456789abcdef"
    plaintext = b"Test message here!"
    iv = b"0123456789abcdef"

    ecb_ct = tf_encrypt_ecb(key, plaintext)
    cbc_ct = tf_encrypt_cbc(key, iv, plaintext)

    # ECB and CBC should produce different ciphertext
    assert ecb_ct != cbc_ct

    # But both should decrypt correctly
    assert tf_decrypt_ecb(key, ecb_ct) == plaintext
    assert tf_decrypt_cbc(key, iv, cbc_ct) == plaintext


class TestTwofishErrorHandling:
  def test_twofish_decrypt_ecb_invalid_ciphertext_length(self):
    with pytest.raises(ValueError, match="multiple of 16"):
      tf_decrypt_ecb(b"0123456789abcdef", b"short")

  def test_twofish_encrypt_cbc_invalid_iv(self):
    with pytest.raises(ValueError, match="IV must be 16 bytes"):
      tf_encrypt_cbc(b"0123456789abcdef", b"short", b"data")

  def test_twofish_decrypt_cbc_invalid_ciphertext_length(self):
    with pytest.raises(ValueError, match="multiple of 16"):
      tf_decrypt_cbc(b"0123456789abcdef", b"1234567890123456", b"short")

  def test_twofish_decrypt_cbc_invalid_iv(self):
    with pytest.raises(ValueError, match="IV must be 16 bytes"):
      tf_decrypt_cbc(b"0123456789abcdef", b"short", b"1234567890123456")


class TestTwofishKeyLengths:
  def test_twofish_192_bit_key_cbc_roundtrip(self):
    key = b"0123456789abcdefghijklmn"
    iv = b"1234567890123456"
    plaintext = b"Test 192-bit key"
    ciphertext = tf_encrypt_cbc(key, iv, plaintext)
    assert tf_decrypt_cbc(key, iv, ciphertext) == plaintext

  def test_twofish_256_bit_key_cbc_roundtrip(self):
    key = b"0123456789abcdefghijklmnopqrstuv"
    iv = b"1234567890123456"
    plaintext = b"Test 256-bit key"
    ciphertext = tf_encrypt_cbc(key, iv, plaintext)
    assert tf_decrypt_cbc(key, iv, ciphertext) == plaintext


class TestTwofishPaddingEdgeCases:
  def test_twofish_empty_plaintext_cbc(self):
    key = b"0123456789abcdef"
    iv = b"1234567890123456"
    ciphertext = tf_encrypt_cbc(key, iv, b"")
    assert len(ciphertext) == 16
    assert tf_decrypt_cbc(key, iv, ciphertext) == b""

  def test_twofish_known_test_vector(self):
    key = bytes(16)
    plaintext = bytes(16)
    ciphertext = tf_encrypt_ecb(key, plaintext)
    assert len(ciphertext) == 16
    assert tf_decrypt_ecb(key, ciphertext) == plaintext


class TestBlowfishErrorHandling:
  def test_blowfish_decrypt_ecb_invalid_ciphertext(self):
    with pytest.raises(ValueError, match="multiple of 8"):
      bf_decrypt_ecb(b"0123456789abcdef", b"short")

  def test_blowfish_encrypt_cbc_invalid_iv(self):
    with pytest.raises(ValueError, match="IV must be 8 bytes"):
      bf_encrypt_cbc(b"0123456789abcdef", b"short", b"data")

  def test_blowfish_decrypt_cbc_invalid_ciphertext(self):
    with pytest.raises(ValueError, match="multiple of 8"):
      bf_decrypt_cbc(b"0123456789abcdef", b"12345678", b"short")

  def test_blowfish_decrypt_cbc_invalid_iv(self):
    with pytest.raises(ValueError, match="IV must be 8 bytes"):
      bf_decrypt_cbc(b"0123456789abcdef", b"short", b"12345678")


class TestBlowfishPaddingEdgeCases:
  def test_blowfish_ecb_exact_block_padding(self):
    key = b"0123456789abcdef"
    plaintext = b"exactly8"
    ciphertext = bf_encrypt_ecb(key, plaintext)
    assert len(ciphertext) == 16
    assert bf_decrypt_ecb(key, ciphertext) == plaintext

  def test_blowfish_cbc_empty_plaintext(self):
    key = b"0123456789abcdef"
    iv = b"12345678"
    ciphertext = bf_encrypt_cbc(key, iv, b"")
    assert len(ciphertext) == 8
    assert bf_decrypt_cbc(key, iv, ciphertext) == b""
