# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_sha0.py
# @time    : 2026/3/9 20:13 Mon
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :
import hashlib
import string

import pytest
from Crypto.Hash import *  # noqa: F403

test_cases = [
  "",
  "a",
  "abc",
  "message digest",
  string.ascii_lowercase,
  string.ascii_uppercase,
  string.digits,
  string.hexdigits,
  string.octdigits,
  string.printable,
]


class TestSha:
  @pytest.mark.parametrize(
    ("msg", "expected"),
    [
      (b"", "f96cea198ad1dd5617ac084a3d92c6107708c0ef"),
      (b"a", "37f297772fae4cb1ba39b6cf9cf0381180bd62f2"),
      (b"abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
    ],
  )
  def test_sha0(self, msg, expected):
    from crypt.digest.SHA import sha0

    result = sha0.sha0(msg)
    assert result == expected, f"Test case failed. Expected: {expected}, Got: {result}"

  @pytest.mark.parametrize(
    "msg",
    [bytes(test_case, "utf-8") for test_case in test_cases],
  )
  def test_sha1(self, msg):
    from crypt.digest.SHA import sha1

    result_custom = sha1.sha1(msg)
    result_hashlib = hashlib.sha1(msg).hexdigest()  # noqa: S324
    result_crypto = SHA1.new(msg).hexdigest()

    assert result_custom == result_hashlib == result_crypto, (
      f"Test case failed for msg: {msg}"
    )

  @pytest.mark.parametrize(
    "msg",
    [bytes(test_case, "utf-8") for test_case in test_cases],
  )
  def test_sha2_224(self, msg):
    from crypt.digest.SHA import sha2_224

    result = sha2_224.sha224_hex(msg)
    assert result == SHA224.new(msg).hexdigest(), f"Test case failed for msg: {msg}"

  @pytest.mark.parametrize(
    "msg",
    [bytes(test_case, "utf-8") for test_case in test_cases],
  )
  def test_sha2_256(self, msg):
    from crypt.digest.SHA import sha2_256

    result = sha2_256.sha256(msg)
    assert result == SHA256.new(msg).hexdigest(), f"Test case failed for msg: {msg}"

  @pytest.mark.parametrize(
    "msg",
    [bytes(test_case, "utf-8") for test_case in test_cases],
  )
  def test_sha2_384(self, msg):
    from crypt.digest.SHA import sha2_384

    result = sha2_384.sha384_hex(msg)
    assert result == SHA384.new(msg).hexdigest(), f"Test case failed for msg: {msg}"
