# @author  : azwpayne(https://github.com/azwpayne)
# @name    : atbash_cipher.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 阿塔巴什密码加密和解密实现

from string import ascii_lowercase, ascii_uppercase


def _create_atbash_table() -> dict[int, int]:
  """创建阿塔巴什转换表"""
  # 阿塔巴什：A <-> Z, B <-> Y, C <-> X, ...
  lower_reversed = ascii_lowercase[::-1]
  upper_reversed = ascii_uppercase[::-1]
  return str.maketrans(
    ascii_lowercase + ascii_uppercase, lower_reversed + upper_reversed
  )


# 预计算转换表
_ATBASH_TABLE = _create_atbash_table()


def encrypt(text: str) -> str:
  """
  使用阿塔巴什密码加密文本

  阿塔巴什密码将字母表的第一个字母与最后一个字母互换，
  第二个与倒数第二个互换，以此类推。

  A <-> Z, B <-> Y, C <-> X, ...

  参数:
      text: 待加密的字符串

  返回:
      加密后的字符串

  示例:
      >>> encrypt("Hello")
      'Svool'
      >>> encrypt("ABCxyz")
      'ZYXcba'
  """
  return text.translate(_ATBASH_TABLE)


def decrypt(text: str) -> str:
  """
  使用阿塔巴什密码解密文本

  阿塔巴什密码是自逆的，加密和解密使用相同的操作

  参数:
      text: 待解密的字符串

  返回:
      解密后的字符串
  """
  return encrypt(text)  # 阿塔巴什是自逆的


# Aliases for comprehensive test compatibility
atbash_encrypt = encrypt
atbash_decrypt = decrypt


def encrypt_hebrew(text: str) -> str:
  """
  使用希伯来字母表的阿塔巴什密码

  原始阿塔巴什密码用于希伯来字母表
  希伯来字母表: א ב ג ד ה ו ז ח ט י כ ל מ נ ס ע פ צ ק ר ש ת
  (共22个字母)

  参数:
      text: 待加密的希伯来文本

  返回:
      加密后的文本

  注意:
      这是一个概念实现，实际希伯来字母处理需要Unicode支持
  """
  # 希伯来字母表 Unicode 范围
  hebrew_start = 0x05D0  # א
  hebrew_end = 0x05EA  # ת

  result = []
  for char in text:
    code = ord(char)
    if hebrew_start <= code <= hebrew_end:
      # 反转位置
      reversed_code = hebrew_end - (code - hebrew_start)
      result.append(chr(reversed_code))
    else:
      result.append(char)

  return "".join(result)


if __name__ == "__main__":
  # 测试阿塔巴什密码
  test_cases = [
    "Hello World",
    "ABC XYZ",
    "abcdefghijklmnopqrstuvwxyz",
    "Atbash",
  ]

  print("阿塔巴什密码测试:")
  print("=" * 50)

  for text in test_cases:
    encrypted = encrypt(text)
    decrypted = decrypt(encrypted)
    print(f"原文: {text}")
    print(f"加密: {encrypted}")
    print(f"解密: {decrypted}")
    print(f"自逆验证: {text == decrypted}")
    print()

  # 圣经示例
  print("=" * 50)
  print("圣经中的阿塔巴什密码示例:")
  bible_text = "Babel"  # 巴比伦
  encrypted = encrypt(bible_text)
  print(f"'{bible_text}' 加密为: '{encrypted}'")
