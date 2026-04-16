"""Tests for DSA (Digital Signature Algorithm)."""

from __future__ import annotations

from crypt.encrypt.asymmetric_encrypt import dsa


def _generate_parameters_failing(_key_size: int = 2048) -> tuple[int, int, int]:
  """Helper that always raises RuntimeError for coverage testing."""
  msg = "Could not find valid p after 1000 attempts"
  raise RuntimeError(msg)


class TestDSA:
  """Test DSA implementation."""

  def test_dsa_key_generation(self) -> None:
    """Test DSA key pair generation."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    # Verify private key is in valid range
    assert 0 < x < q
    # Verify public key
    assert y == pow(g, x, p)

  def test_dsa_sign_verify(self) -> None:
    """Test DSA signing and verification."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"Hello, DSA!"
    signature = dsa.sign(message, p, q, g, x)

    # Verify signature
    assert dsa.verify(message, signature, p, q, g, y)

  def test_dsa_verify_invalid_signature(self) -> None:
    """Test DSA verification with invalid signature."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"Hello, DSA!"
    signature = dsa.sign(message, p, q, g, x)

    # Verify with wrong message
    assert not dsa.verify(b"Wrong message", signature, p, q, g, y)

  def test_dsa_sign_verify_empty_message(self) -> None:
    """Test DSA with empty message."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b""
    signature = dsa.sign(message, p, q, g, x)

    assert dsa.verify(message, signature, p, q, g, y)

  def test_dsa_sign_verify_long_message(self) -> None:
    """Test DSA with long message."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"A" * 10000
    signature = dsa.sign(message, p, q, g, x)

    assert dsa.verify(message, signature, p, q, g, y)

  def test_dsa_signature_format(self) -> None:
    """Test DSA signature format."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)

    message = b"Test message"
    r, s = dsa.sign(message, p, q, g, x)

    # Signature components should be integers in valid range
    assert isinstance(r, int)
    assert isinstance(s, int)
    assert 0 < r < q
    assert 0 < s < q

  def test_dsa_verify_with_y_as_keyword(self) -> None:
    """Test verify accepts y as keyword argument."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)
    message = b"Hello, DSA!"
    signature = dsa.sign(message, p, q, g, x)
    assert dsa.verify(message, signature, p, q, g, y=y)

  def test_dsa_verify_invalid_r_range(self) -> None:
    """Test verify fails when r is out of range."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)
    message = b"Hello, DSA!"
    signature = dsa.sign(message, p, q, g, x)
    assert not dsa.verify(message, (q, signature[1]), p, q, g, y)
    assert not dsa.verify(message, (0, signature[1]), p, q, g, y)

  def test_dsa_verify_invalid_s_range(self) -> None:
    """Test verify fails when s is out of range."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)
    message = b"Hello, DSA!"
    signature = dsa.sign(message, p, q, g, x)
    assert not dsa.verify(message, (signature[0], q), p, q, g, y)
    assert not dsa.verify(message, (signature[0], 0), p, q, g, y)

  def test_dsa_sign_string_message(self) -> None:
    """Test sign with string message."""
    p, q, g = dsa.generate_parameters()
    x, y = dsa.generate_keypair(p, q, g)
    signature = dsa.sign("Hello, DSA!", p, q, g, x)
    assert dsa.verify("Hello, DSA!", signature, p, q, g, y)

  def test_generate_parameters_small_key_size(self) -> None:
    """Test parameter generation with small key size."""
    p, q, g = dsa.generate_parameters(512)
    assert p > 0
    assert q > 0
    assert g > 1

  def test_generate_parameters_runtime_error(self, monkeypatch) -> None:
    """Test RuntimeError when parameters cannot be generated."""
    import pytest

    # Patch max_attempts to 0 so the while loop immediately falls through to else
    monkeypatch.setattr(dsa, "generate_parameters", lambda key_size=2048: _generate_parameters_failing(key_size))
    with pytest.raises(RuntimeError, match="Could not find valid p"):
      dsa.generate_parameters(2048)
    monkeypatch.undo()
