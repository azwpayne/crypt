# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_base.py
# @time    : 2026/3/10 12:55 Tue
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :
import binascii

import pytest
from tests import BYTE_TEST_CASES


@pytest.mark.parametrize("msg", BYTE_TEST_CASES)
class TestBase:
  def test_base16(self, msg):
    from crypt.encode import base16

    result = binascii.hexlify(msg).decode("ascii")
    assert base16.base16_encode(msg) == result.upper(), (
      f"Test case failed for msg: {msg}"
    )
