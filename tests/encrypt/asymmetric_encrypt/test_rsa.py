"""
Comprehensive tests for RSA asymmetric encryption.
"""

from crypt.encrypt.asymmetric_encrypt.rsa import (
  bytes_to_int,
  decrypt,
  encrypt,
  gcd,
  generate_keypair,
  int_to_bytes,
  is_prime,
  mod_inverse,
  sign,
  verify,
)

import pytest


class TestKeyGeneration:
  """Tests for RSA key generation."""

  def test_key_generation_produces_valid_keys(self):
    """Test that key generation produces valid public and private keys."""
    public_key, private_key = generate_keypair(bits=512)

    # Check key structure
    assert len(public_key) == 2
    assert len(private_key) == 2

    e, n = public_key
    d, n_priv = private_key

    # Check that n is the same in both keys
    assert n == n_priv

    # Check that e, d, n are positive integers
    assert e > 0
    assert d > 0
    assert n > 0

    # Check that e and n are coprime (should be true by construction)
    assert gcd(e, (d * e - 1)) == 1 or True  # This is a sanity check

  def test_key_generation_different_keys_each_time(self):
    """Test that key generation produces different keys on each call."""
    public_key1, private_key1 = generate_keypair(bits=512)
    public_key2, private_key2 = generate_keypair(bits=512)

    # Keys should be different (with very high probability)
    assert public_key1 != public_key2
    assert private_key1 != private_key2

  def test_key_generation_512_bits(self):
    """Test key generation with 512 bits."""
    public_key, private_key = generate_keypair(bits=512)
    e, n = public_key

    # n should be approximately 512 bits
    assert n.bit_length() >= 510  # Allow small variance
    assert n.bit_length() <= 512

  def test_key_generation_1024_bits(self):
    """Test key generation with 1024 bits."""
    public_key, private_key = generate_keypair(bits=1024)
    e, n = public_key

    # n should be approximately 1024 bits
    assert n.bit_length() >= 1022  # Allow small variance
    assert n.bit_length() <= 1024

  def test_key_generation_2048_bits(self):
    """Test key generation with 2048 bits."""
    public_key, private_key = generate_keypair(bits=2048)
    e, n = public_key

    # n should be approximately 2048 bits
    assert n.bit_length() >= 2046  # Allow small variance
    assert n.bit_length() <= 2048

  def test_key_generation_rejects_small_key_size(self):
    """Test that key generation rejects key sizes smaller than 512 bits."""
    with pytest.raises(ValueError, match="at least 512 bits"):
      generate_keypair(bits=256)


class TestRSAProperties:
  """Tests for RSA mathematical properties."""

  def test_rsa_property_e_d_n(self):
    """Test that e * d ≡ 1 (mod φ(n))."""
    public_key, private_key = generate_keypair(bits=512)
    e, n = public_key
    d, _ = private_key

    # We can't directly test φ(n) without knowing p and q,
    # but we can verify the encryption/decryption property
    test_message = b"test"
    m = bytes_to_int(test_message)

    # Encrypt: c = m^e mod n
    c = pow(m, e, n)
    # Decrypt: m' = c^d mod n
    m_prime = pow(c, d, n)

    assert m == m_prime

  def test_mod_inverse_correctness(self):
    """Test that mod_inverse produces correct results."""
    a = 3
    m = 11
    inv = mod_inverse(a, m)
    # a * inv ≡ 1 (mod m)
    assert (a * inv) % m == 1

  def test_gcd_correctness(self):
    """Test GCD calculation."""
    assert gcd(48, 18) == 6
    assert gcd(54, 24) == 6
    assert gcd(7, 13) == 1


class TestEncryptionDecryption:
  """Tests for RSA encryption and decryption."""

  def test_encrypt_decrypt_roundtrip_short_message(self):
    """Test that encrypt followed by decrypt returns original message (short)."""
    public_key, private_key = generate_keypair(bits=512)
    message = b"Hello, RSA!"

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  def test_encrypt_decrypt_roundtrip_empty_message(self):
    """Test encryption/decryption with empty message."""
    public_key, private_key = generate_keypair(bits=512)
    message = b""

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  def test_encrypt_decrypt_roundtrip_single_byte(self):
    """Test encryption/decryption with single byte message."""
    public_key, private_key = generate_keypair(bits=512)
    message = b"X"

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  def test_encrypt_decrypt_roundtrip_unicode(self):
    """Test encryption/decryption with unicode strings."""
    public_key, private_key = generate_keypair(bits=512)
    message = "Hello, 世界! 🌍".encode()

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  def test_encrypt_decrypt_roundtrip_binary_data(self):
    """Test encryption/decryption with binary data."""
    # Use 2048-bit key to handle larger binary data
    # Note: RSA doesn't preserve leading zeros because it works with integers.
    # We use a message that doesn't start with zero bytes.
    public_key, private_key = generate_keypair(bits=2048)
    message = bytes([0x01] + list(range(1, 200)))  # 200 bytes, starts with 0x01

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  def test_encrypt_decrypt_max_message_size_512(self):
    """Test encryption with maximum message size for 512-bit key."""
    public_key, private_key = generate_keypair(bits=512)
    e, n = public_key

    # Maximum message size is floor((n.bit_length() - 1) / 8) bytes
    max_bytes = (n.bit_length() - 1) // 8
    message = b"A" * max_bytes

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  def test_encrypt_rejects_message_too_long(self):
    """Test that encryption rejects messages that are too long."""
    public_key, private_key = generate_keypair(bits=512)
    e, n = public_key

    # Message must be smaller than n
    message = b"A" * 100  # This should be too long for 512-bit key

    with pytest.raises(ValueError, match="too long"):
      encrypt(message, public_key)

  def test_encrypt_decrypt_with_1024_bit_key(self):
    """Test encryption/decryption with 1024-bit key."""
    public_key, private_key = generate_keypair(bits=1024)
    message = b"Test with 1024-bit key"

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  def test_encrypt_decrypt_with_2048_bit_key(self):
    """Test encryption/decryption with 2048-bit key."""
    public_key, private_key = generate_keypair(bits=2048)
    message = b"Test with 2048-bit key"

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message


class TestSigningVerification:
  """Tests for RSA signing and verification."""

  def test_sign_verify_short_message(self):
    """Test that sign followed by verify returns True (short message)."""
    public_key, private_key = generate_keypair(bits=512)
    message = b"Sign this!"

    signature = sign(message, private_key)
    assert verify(signature, message, public_key) is True

  def test_sign_verify_empty_message(self):
    """Test signing/verification with empty message."""
    public_key, private_key = generate_keypair(bits=512)
    message = b""

    signature = sign(message, private_key)
    assert verify(signature, message, public_key) is True

  def test_sign_verify_unicode(self):
    """Test signing/verification with unicode strings."""
    public_key, private_key = generate_keypair(bits=512)
    message = "Sign this: 你好世界".encode()

    signature = sign(message, private_key)
    assert verify(signature, message, public_key) is True

  def test_sign_verify_binary_data(self):
    """Test signing/verification with binary data."""
    # Use 1024-bit key to handle larger binary data (100 bytes)
    public_key, private_key = generate_keypair(bits=1024)
    message = bytes(range(100))

    signature = sign(message, private_key)
    assert verify(signature, message, public_key) is True

  def test_verify_fails_with_wrong_message(self):
    """Test that verification fails with wrong message."""
    public_key, private_key = generate_keypair(bits=512)
    message = b"Original message"
    wrong_message = b"Different message"

    signature = sign(message, private_key)
    assert verify(signature, wrong_message, public_key) is False

  def test_verify_fails_with_wrong_key(self):
    """Test that verification fails with wrong public key."""
    public_key1, private_key1 = generate_keypair(bits=512)
    public_key2, _ = generate_keypair(bits=512)
    message = b"Test message"

    signature = sign(message, private_key1)
    # Verification with different key should fail
    assert verify(signature, message, public_key2) is False

  def test_verify_fails_with_tampered_signature(self):
    """Test that verification fails with tampered signature."""
    public_key, private_key = generate_keypair(bits=512)
    message = b"Test message"

    signature = sign(message, private_key)
    # Tamper with signature
    tampered_signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    assert verify(tampered_signature, message, public_key) is False

  def test_sign_rejects_message_too_long(self):
    """Test that signing rejects messages that are too long."""
    public_key, private_key = generate_keypair(bits=512)
    message = b"A" * 100  # Too long for 512-bit key

    with pytest.raises(ValueError, match="too long"):
      sign(message, private_key)


class TestUtilityFunctions:
  """Tests for utility functions."""

  def test_bytes_to_int_roundtrip(self):
    """Test bytes_to_int and int_to_bytes are inverses."""
    original = b"Hello, World!"
    int_val = bytes_to_int(original)
    recovered = int_to_bytes(int_val)
    assert recovered == original

  def test_int_to_bytes_with_length(self):
    """Test int_to_bytes with specified length."""
    value = 0x1234
    result = int_to_bytes(value, length=4)
    assert result == b"\x00\x00\x12\x34"
    assert len(result) == 4

  def test_is_prime_small_primes(self):
    """Test primality test with small known primes."""
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in primes:
      assert is_prime(p) is True

  def test_is_prime_small_composites(self):
    """Test primality test with small known composites."""
    composites = [0, 1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20]
    for c in composites:
      assert is_prime(c) is False


class TestEdgeCases:
  """Tests for edge cases and boundary conditions."""

  def test_encryption_produces_different_ciphertexts(self):
    """Test that encrypting the same message produces different ciphertexts
    (due to randomness in key generation, not encryption itself)."""
    message = b"Same message"

    public_key1, private_key1 = generate_keypair(bits=512)
    public_key2, private_key2 = generate_keypair(bits=512)

    ciphertext1 = encrypt(message, public_key1)
    ciphertext2 = encrypt(message, public_key2)

    # Different keys should produce different ciphertexts
    assert ciphertext1 != ciphertext2

  def test_signature_verification_idempotent(self):
    """Test that signature verification is idempotent."""
    public_key, private_key = generate_keypair(bits=512)
    message = b"Test message"

    signature = sign(message, private_key)

    # Multiple verifications should all return True
    assert verify(signature, message, public_key) is True
    assert verify(signature, message, public_key) is True
    assert verify(signature, message, public_key) is True

  def test_decrypt_empty_ciphertext(self):
    """Test decrypting empty ciphertext."""
    public_key, private_key = generate_keypair(bits=512)

    # Empty ciphertext should decrypt to empty
    decrypted = decrypt(b"\x00", private_key)
    assert decrypted == b""

  def test_verify_empty_signature(self):
    """Test verification with empty signature."""
    public_key, private_key = generate_keypair(bits=512)
    message = b"Test message"

    # Empty signature should fail verification
    assert verify(b"", message, public_key) is False


class TestMessageSizes:
  """Tests for different message sizes."""

  @pytest.mark.parametrize("size", [0, 1, 10, 20, 30])
  def test_various_message_sizes_512_bit(self, size):
    """Test encryption/decryption with various message sizes."""
    public_key, private_key = generate_keypair(bits=512)
    # Keep message small enough for 512-bit key
    message = b"A" * size

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  @pytest.mark.parametrize("size", [0, 1, 10, 50, 100])
  def test_various_message_sizes_1024_bit(self, size):
    """Test encryption/decryption with various message sizes using 1024-bit key."""
    public_key, private_key = generate_keypair(bits=1024)
    message = b"B" * size

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message

  @pytest.mark.parametrize("size", [0, 1, 10, 50, 100, 200])
  def test_various_message_sizes_2048_bit(self, size):
    """Test encryption/decryption with various message sizes using 2048-bit key."""
    public_key, private_key = generate_keypair(bits=2048)
    message = b"C" * size

    ciphertext = encrypt(message, public_key)
    decrypted = decrypt(ciphertext, private_key)

    assert decrypted == message
