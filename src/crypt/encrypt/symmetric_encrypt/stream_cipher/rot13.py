# @author  : azwpayne(https://github.com/azwpayne)
# @name    : rot13.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : ROT13加密和解密实现（凯撒密码的特例，偏移量为13）

from string import ascii_lowercase, ascii_uppercase


def _create_rot13_table() -> dict[int, int]:
  """创建ROT13转换表"""
  # ROT13 将字母表前半部分映射到后半部分
  lower = ascii_lowercase[13:] + ascii_lowercase[:13]
  upper = ascii_uppercase[13:] + ascii_uppercase[:13]
  return str.maketrans(ascii_lowercase + ascii_uppercase, lower + upper)


# 预计算转换表
_ROT13_TABLE = _create_rot13_table()


def encrypt(text: str) -> str:
  """
  使用ROT13加密文本

  ROT13是凯撒密码的特例，偏移量为13。
  由于字母表有26个字母，ROT13的加密和解密是相同的操作。

  参数:
      text: 待加密的字符串

  返回:
      加密后的字符串

  示例:
      >>> encrypt("Hello")
      'Uryyb'
      >>> encrypt(encrypt("Hello"))
      'Hello'
  """
  return text.translate(_ROT13_TABLE)


def decrypt(text: str) -> str:
  """
  使用ROT13解密文本

  ROT13的加密和解密是相同的操作

  参数:
      text: 待解密的字符串

  返回:
      解密后的字符串
  """
  return encrypt(text)  # ROT13是自逆的


# Alias for comprehensive test compatibility
rot13 = encrypt


if __name__ == "__main__":
  # 测试ROT13
  test_texts = [
    "Hello World",
    "Python",
    "ROT13",
    "abcdefghijklmnopqrstuvwxyz",
  ]

  for text in test_texts:
    encrypted = encrypt(text)
    decrypted = decrypt(encrypted)
    print(f"原文: {text}")
    print(f"加密: {encrypted}")
    print(f"解密: {decrypted}")
    print(f"自逆验证: {text == decrypted}")
    print()
