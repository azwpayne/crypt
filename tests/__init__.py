# @author  : azwpayne(https://github.com/azwpayne)
# @name    : __init__.py.py
# @time    : 2026/3/10 12:57 Tue
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :
import string

TEST_CASES = [
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

BYTE_TEST_CASES = [bytes(test_case, "utf-8") for test_case in TEST_CASES]
