# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_sha0.py
# @time    : 2026/3/9 20:13 Mon
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :
import hashlib
import unittest

from Crypto.Hash import SHA1


class TestSHA(unittest.TestCase):
    """
    SHA0 测试
    """

    def test_sha0(self):
        from crypt.digest.SHA import sha0
        test_cases = [
            (b"", "f96cea198ad1dd5617ac084a3d92c6107708c0ef"),
            (b"a", "37f297772fae4cb1ba39b6cf9cf0381180bd62f2"),
            (b"abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
        ]
        for i, (msg, expected) in enumerate(test_cases):
            result = sha0.sha0(msg)
            assert result == expected, f"Test case {i} failed. Expected: {expected}, Got: {result}"

    def test_sha1(self):
        from crypt.digest.SHA import sha1
        test_cases = [
            b"",
            b"a",
            b"abc",
        ]
        for i, (msg) in enumerate(test_cases):
            assert sha1.sha1(msg) == hashlib.sha1(msg).hexdigest() == SHA1.new(
                msg).hexdigest(), f"Test case {i} failed."
