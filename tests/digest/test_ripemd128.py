"""Tests for RIPEMD-128."""

from crypt.digest.ripemd128 import ripemd128, ripemd128_hex


class TestRIPEMD128:
  def test_output_length(self):
    assert len(ripemd128(b"hello")) == 16

  def test_hex_length(self):
    assert len(ripemd128_hex(b"hello")) == 32

  def test_empty_known(self):
    # RIPEMD-128("") = cdf26213a150dc3ecb610f18f6b38b46
    assert ripemd128_hex(b"") == "cdf26213a150dc3ecb610f18f6b38b46"

  def test_abc_known(self):
    # RIPEMD-128("abc") = c14a12199c66e4ba84636b0f69144c77
    assert ripemd128_hex(b"abc") == "c14a12199c66e4ba84636b0f69144c77"

  def test_consistency(self):
    assert ripemd128(b"test") == ripemd128(b"test")

  def test_different_inputs_differ(self):
    assert ripemd128(b"abc") != ripemd128(b"def")
