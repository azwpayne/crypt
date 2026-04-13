# @author  : azwpayne(https://github.com/azwpayne)
# @name    : simple_substitution.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 简单替换密码加密和解密实现

import random
from string import ascii_uppercase


def _validate_key(key: str) -> None:
  """
  验证密钥是否有效

  密钥必须是26个字母的排列
  """
  if len(key) != 26:
    msg = f"密钥长度必须为26，当前为{len(key)}"
    raise ValueError(msg)

  key_upper = key.upper()
  if set(key_upper) != set(ascii_uppercase):
    msg = "密钥必须包含A-Z的所有字母且不重复"
    raise ValueError(msg)


def encrypt(text: str, key: str) -> str:
  """
  使用简单替换密码加密文本

  参数:
      text: 待加密的字符串
      key: 替换密钥（26个字母的排列，表示A-Z分别替换为什么）

  返回:
      加密后的字符串

  示例:
      >>> key = "QWERTYUIOPASDFGHJKLZXCVBNM"
      >>> encrypt("HELLO", key)
      'ITSSG'
  """
  _validate_key(key)

  # 创建替换映射
  key_upper = key.upper()
  encrypt_map = dict(zip(ascii_uppercase, key_upper, strict=False))

  result = []
  for char in text:
    if char.isascii() and char.isalpha():
      upper_char = char.upper()
      encrypted = encrypt_map[upper_char]
      # 保持原始大小写
      result.append(encrypted if char.isupper() else encrypted.lower())
    else:
      result.append(char)

  return "".join(result)


def decrypt(text: str, key: str) -> str:
  """
  使用简单替换密码解密文本

  参数:
      text: 待解密的字符串
      key: 替换密钥

  返回:
      解密后的字符串
  """
  _validate_key(key)

  # 创建反向映射
  key_upper = key.upper()
  decrypt_map = dict(zip(key_upper, ascii_uppercase, strict=False))

  result = []
  for char in text:
    if char.isascii() and char.isalpha():
      upper_char = char.upper()
      decrypted = decrypt_map[upper_char]
      # 保持原始大小写
      result.append(decrypted if char.isupper() else decrypted.lower())
    else:
      result.append(char)

  return "".join(result)


def generate_random_key() -> str:
  """
  生成随机密钥

  返回:
      26个字母的随机排列
  """
  letters = list(ascii_uppercase)
  random.shuffle(letters)
  return "".join(letters)


def generate_key_from_keyword(keyword: str) -> str:
  """
  从关键词生成密钥

  关键词在前，剩余字母按字母表顺序排列

  参数:
      keyword: 关键词

  返回:
      生成的密钥

  示例:
      >>> generate_key_from_keyword("KEYWORD")
      'KEYWORDABCFGHILMNPQSTUVXZ'
  """
  # 清理关键词
  cleaned = "".join(c.upper() for c in keyword if c.isascii() and c.isalpha())

  # 去重但保持顺序
  seen = set()
  unique_keyword = []
  for c in cleaned:
    if c not in seen:
      seen.add(c)
      unique_keyword.append(c)

  # 添加剩余字母
  remaining = [c for c in ascii_uppercase if c not in seen]

  return "".join(unique_keyword) + "".join(remaining)


def frequency_analysis(text: str) -> dict[str, float]:
  """
  频率分析

  计算文本中各字母的出现频率

  参数:
      text: 待分析的文本

  返回:
      字母频率字典（百分比）
  """
  # 只统计字母
  letters = [c.upper() for c in text if c.isascii() and c.isalpha()]
  total = len(letters)

  if total == 0:
    return {}

  # 统计频率
  freq: dict[str, int] = {}
  for c in letters:
    freq[c] = freq.get(c, 0) + 1

  # 转换为百分比
  return {c: (count / total) * 100 for c, count in sorted(freq.items())}


if __name__ == "__main__":
  # 测试简单替换密码
  source_text = "HELLO WORLD"

  # 使用关键词生成密钥
  key = generate_key_from_keyword("KEYWORD")
  print(f"原文: {source_text}")
  print(f"密钥: {key}")

  encrypted = encrypt(source_text, key)
  print(f"加密后: {encrypted}")

  decrypted = decrypt(encrypted, key)
  print(f"解密后: {decrypted}")

  # 测试随机密钥
  print("\n--- 随机密钥 ---")
  random_key = generate_random_key()
  print(f"随机密钥: {random_key}")

  encrypted_random = encrypt(source_text, random_key)
  print(f"加密: {encrypted_random}")

  decrypted_random = decrypt(encrypted_random, random_key)
  print(f"解密: {decrypted_random}")

  # 频率分析
  print("\n--- 频率分析 ---")
  freq = frequency_analysis(source_text)
  for letter, percentage in freq.items():
    print(f"  {letter}: {percentage:.1f}%")
