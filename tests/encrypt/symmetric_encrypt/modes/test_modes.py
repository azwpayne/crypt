# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_modes.py
# @time    : 2026/3/15
# @desc    : Tests for authenticated encryption modes (CCM, GCM)


from crypt.encrypt.symmetric_encrypt import ccm, gcm


class TestCCM:
  """Tests for CCM (Counter with CBC-MAC) mode."""

  def test_ccm_roundtrip_basic(self):
    """Test basic CCM encryption/decryption roundtrip."""
    key = b"\x00" * 16
    nonce = b"\x01" * 12
    plaintext = b"Hello, World!"
    aad = b"authenticated data"

    ciphertext, tag = ccm.ccm_encrypt(key, nonce, plaintext, aad)
    decrypted = ccm.ccm_decrypt(key, nonce, ciphertext, tag, aad)

    assert decrypted == plaintext

  def test_ccm_roundtrip_no_aad(self):
    """Test CCM roundtrip without additional authenticated data."""
    key = b"\xab" * 16
    nonce = b"\xcd" * 12
    plaintext = b"Test message without AAD"

    ciphertext, tag = ccm.ccm_encrypt(key, nonce, plaintext)
    decrypted = ccm.ccm_decrypt(key, nonce, ciphertext, tag)

    assert decrypted == plaintext

  def test_ccm_empty_plaintext(self):
    """Test CCM with empty plaintext."""
    key = b"\x12" * 16
    nonce = b"\x34" * 12
    plaintext = b""

    ciphertext, tag = ccm.ccm_encrypt(key, nonce, plaintext)
    decrypted = ccm.ccm_decrypt(key, nonce, ciphertext, tag)

    assert decrypted == plaintext

  def test_ccm_different_mac_lengths(self):
    """Test CCM with different MAC tag lengths."""
    key = b"\x00" * 16
    nonce = b"\x01" * 12
    plaintext = b"Test message"

    for mac_len in [4, 6, 8, 10, 12, 14, 16]:
      ciphertext, tag = ccm.ccm_encrypt(key, nonce, plaintext, mac_len=mac_len)
      assert len(tag) == mac_len
      decrypted = ccm.ccm_decrypt(key, nonce, ciphertext, tag)
      assert decrypted == plaintext

  def test_ccm_wrong_tag_fails(self):
    """Test that decryption fails with wrong tag."""
    key = b"\x00" * 16
    nonce = b"\x01" * 12
    plaintext = b"Secret message"

    ciphertext, tag = ccm.ccm_encrypt(key, nonce, plaintext)
    wrong_tag = b"\xff" * len(tag)

    decrypted = ccm.ccm_decrypt(key, nonce, ciphertext, wrong_tag)
    assert decrypted is None

  def test_ccm_tampered_ciphertext_fails(self):
    """Test that decryption fails with tampered ciphertext."""
    key = b"\x00" * 16
    nonce = b"\x01" * 12
    plaintext = b"Secret message"

    ciphertext, tag = ccm.ccm_encrypt(key, nonce, plaintext)
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

    decrypted = ccm.ccm_decrypt(key, nonce, tampered, tag)
    assert decrypted is None

  def test_ccm_different_keys_produce_different_ciphertexts(self):
    """Test that different keys produce different ciphertexts."""
    nonce = b"\x01" * 12
    plaintext = b"Same message"

    key1 = b"\x00" * 16
    key2 = b"\x11" * 16

    ct1, _ = ccm.ccm_encrypt(key1, nonce, plaintext)
    ct2, _ = ccm.ccm_encrypt(key2, nonce, plaintext)

    assert ct1 != ct2

  def test_ccm_different_nonces_produce_different_ciphertexts(self):
    """Test that different nonces produce different ciphertexts."""
    key = b"\x00" * 16
    plaintext = b"Same message"

    nonce1 = b"\x01" * 12
    nonce2 = b"\x02" * 12

    ct1, _ = ccm.ccm_encrypt(key, nonce1, plaintext)
    ct2, _ = ccm.ccm_encrypt(key, nonce2, plaintext)

    assert ct1 != ct2


class TestGCM:
  """Tests for GCM (Galois/Counter Mode)."""

  def test_gcm_roundtrip_basic(self):
    """Test basic GCM encryption/decryption roundtrip."""
    key = b"\x00" * 16
    iv = b"\x01" * 12
    plaintext = b"Hello, World!"
    aad = b"authenticated data"

    ciphertext, tag = gcm.gcm_encrypt(key, iv, plaintext, aad)
    decrypted = gcm.gcm_decrypt(key, iv, ciphertext, tag, aad)

    assert decrypted == plaintext

  def test_gcm_roundtrip_no_aad(self):
    """Test GCM roundtrip without additional authenticated data."""
    key = b"\xab" * 16
    iv = b"\xcd" * 12
    plaintext = b"Test message without AAD"

    ciphertext, tag = gcm.gcm_encrypt(key, iv, plaintext)
    decrypted = gcm.gcm_decrypt(key, iv, ciphertext, tag)

    assert decrypted == plaintext

  def test_gcm_empty_plaintext(self):
    """Test GCM with empty plaintext."""
    key = b"\x12" * 16
    iv = b"\x34" * 12
    plaintext = b""

    ciphertext, tag = gcm.gcm_encrypt(key, iv, plaintext)
    decrypted = gcm.gcm_decrypt(key, iv, ciphertext, tag)

    assert decrypted == plaintext

  def test_gcm_tag_length(self):
    """Test that GCM produces correct tag length."""
    key = b"\x00" * 16
    iv = b"\x01" * 12
    plaintext = b"Test message"

    ciphertext, tag = gcm.gcm_encrypt(key, iv, plaintext)
    assert len(tag) == 16

  def test_gcm_wrong_tag_fails(self):
    """Test that decryption fails with wrong tag."""
    key = b"\x00" * 16
    iv = b"\x01" * 12
    plaintext = b"Secret message"

    ciphertext, tag = gcm.gcm_encrypt(key, iv, plaintext)
    wrong_tag = b"\xff" * 16

    decrypted = gcm.gcm_decrypt(key, iv, ciphertext, wrong_tag)
    assert decrypted is None

  def test_gcm_tampered_ciphertext_fails(self):
    """Test that decryption fails with tampered ciphertext."""
    key = b"\x00" * 16
    iv = b"\x01" * 12
    plaintext = b"Secret message"

    ciphertext, tag = gcm.gcm_encrypt(key, iv, plaintext)
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

    decrypted = gcm.gcm_decrypt(key, iv, tampered, tag)
    assert decrypted is None

  def test_gcm_different_keys_produce_different_ciphertexts(self):
    """Test that different keys produce different ciphertexts."""
    iv = b"\x01" * 12
    plaintext = b"Same message"

    key1 = b"\x00" * 16
    key2 = b"\x11" * 16

    ct1, _ = gcm.gcm_encrypt(key1, iv, plaintext)
    ct2, _ = gcm.gcm_encrypt(key2, iv, plaintext)

    assert ct1 != ct2

  def test_gcm_different_ivs_produce_different_ciphertexts(self):
    """Test that different IVs produce different ciphertexts."""
    key = b"\x00" * 16
    plaintext = b"Same message"

    iv1 = b"\x01" * 12
    iv2 = b"\x02" * 12

    ct1, _ = gcm.gcm_encrypt(key, iv1, plaintext)
    ct2, _ = gcm.gcm_encrypt(key, iv2, plaintext)

    assert ct1 != ct2

  def test_gcm_aad_affects_tag(self):
    """Test that different AAD produces different tags."""
    key = b"\x00" * 16
    iv = b"\x01" * 12
    plaintext = b"Same message"

    aad1 = b"AAD1"
    aad2 = b"AAD2"

    ct1, tag1 = gcm.gcm_encrypt(key, iv, plaintext, aad1)
    ct2, tag2 = gcm.gcm_encrypt(key, iv, plaintext, aad2)

    # Ciphertexts should be the same (AAD doesn't affect encryption)
    assert ct1 == ct2
    # But tags should be different
    assert tag1 != tag2

  def test_gcm_decrypt_with_wrong_aad_fails(self):
    """Test that decryption with wrong AAD fails."""
    key = b"\x00" * 16
    iv = b"\x01" * 12
    plaintext = b"Secret message"
    aad = b"correct AAD"

    ciphertext, tag = gcm.gcm_encrypt(key, iv, plaintext, aad)
    decrypted = gcm.gcm_decrypt(key, iv, ciphertext, tag, b"wrong AAD")

    assert decrypted is None


class TestModesComparison:
  """Tests comparing CCM and GCM behaviors."""

  def test_both_modes_support_same_interface(self):
    """Test that CCM and GCM have compatible interfaces."""
    key = b"\x00" * 16
    nonce = b"\x01" * 12
    plaintext = b"Test message"
    aad = b"authenticated"

    # Both should support basic encrypt/decrypt operations
    ccm_ct, ccm_tag = ccm.ccm_encrypt(key, nonce, plaintext, aad)
    gcm_ct, gcm_tag = gcm.gcm_encrypt(key, nonce, plaintext, aad)

    # Both should be able to decrypt their own output
    assert ccm.ccm_decrypt(key, nonce, ccm_ct, ccm_tag, aad) == plaintext
    assert gcm.gcm_decrypt(key, nonce, gcm_ct, gcm_tag, aad) == plaintext
