# @author  : azwpayne(https://github.com/azwpayne)
# @name    : vigenere_cipher.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 维吉尼亚密码加密和解密实现

from itertools import cycle


def _char_to_num(char: str) -> int:
  """将字母转换为数字 (A/a=0, B/b=1, ..., Z/z=25)"""
  return ord(char.upper()) - ord("A")


def _num_to_char(num: int) -> str:
  """将数字转换为大写字母"""
  return chr((num % 26) + ord("A"))


def _prepare_key(key: str, length: int) -> str:
  """
  准备密钥，去除非字母字符并循环扩展到指定长度

  参数:
      key: 原始密钥
      length: 需要的长度

  返回:
      处理后的密钥
  """
  cleaned_key = "".join(c for c in key if c.isalpha()).upper()
  if not cleaned_key:
    msg = "密钥必须包含至少一个字母"
    raise ValueError(msg)
  return "".join(c for c, _ in zip(cycle(cleaned_key), range(length)))


def encrypt(text: str, key: str) -> str:
  """
  使用维吉尼亚密码加密文本

  加密公式: C = (P + K) mod 26

  参数:
      text: 待加密的字符串
      key: 加密密钥

  返回:
      加密后的大写字符串
  """
  # 过滤出字母并记录位置
  letters_only = [(i, c) for i, c in enumerate(text) if c.isalpha()]

  if not letters_only:
    return text

  # 准备密钥
  extended_key = _prepare_key(key, len(letters_only))

  # 加密
  result = list(text)
  for (idx, char), key_char in zip(letters_only, extended_key, strict=False):
    p = _char_to_num(char)
    k = _char_to_num(key_char)
    c = (p + k) % 26
    result[idx] = _num_to_char(c)

  return "".join(result)


def decrypt(text: str, key: str) -> str:
  """
  使用维吉尼亚密码解密文本

  解密公式: P = (C - K) mod 26

  参数:
      text: 待解密的字符串
      key: 解密密钥

  返回:
      解密后的大写字符串
  """
  # 过滤出字母并记录位置
  letters_only = [(i, c) for i, c in enumerate(text) if c.isalpha()]

  if not letters_only:
    return text

  # 准备密钥
  extended_key = _prepare_key(key, len(letters_only))

  # 解密
  result = list(text)
  for (idx, char), key_char in zip(letters_only, extended_key, strict=False):
    c = _char_to_num(char)
    k = _char_to_num(key_char)
    p = (c - k) % 26
    result[idx] = _num_to_char(p)

  return "".join(result)


def autokey_encrypt(text: str, key: str) -> str:
  """
  使用自动密钥维吉尼亚密码加密

  自动密钥密码将明文附加到密钥后面作为密钥的一部分

  参数:
      text: 待加密的字符串
      key: 初始密钥

  返回:
      加密后的大写字符串
  """
  # 过滤出字母
  letters = [c for c in text if c.isalpha()]

  if not letters:
    return text

  # 准备初始密钥
  cleaned_key = "".join(c for c in key if c.isalpha()).upper()
  if not cleaned_key:
    msg = "密钥必须包含至少一个字母"
    raise ValueError(msg)

  # 构建自动密钥：密钥 + 明文（大写）
  auto_key = (cleaned_key + "".join(c.upper() for c in letters))[: len(letters)]

  # 加密
  result = list(text)
  letter_idx = 0
  for i, char in enumerate(text):
    if char.isalpha():
      p = _char_to_num(char)
      k = _char_to_num(auto_key[letter_idx])
      c = (p + k) % 26
      result[i] = _num_to_char(c)
      letter_idx += 1

  return "".join(result)


def autokey_decrypt(text: str, key: str) -> str:
  """
  使用自动密钥维吉尼亚密码解密

  参数:
      text: 待解密的字符串
      key: 初始密钥

  返回:
      解密后的大写字符串
  """
  # 过滤出字母
  letters = [(i, c) for i, c in enumerate(text) if c.isalpha()]

  if not letters:
    return text

  # 准备初始密钥
  cleaned_key = "".join(c for c in key if c.isalpha()).upper()
  if not cleaned_key:
    msg = "密钥必须包含至少一个字母"
    raise ValueError(msg)

  # 解密
  result = list(text)
  decrypted_letters = []

  for idx, (pos, char) in enumerate(letters):
    c = _char_to_num(char)

    # 确定使用的密钥字符
    if idx < len(cleaned_key):
      k = _char_to_num(cleaned_key[idx])
    else:
      # 使用已解密的明文作为密钥
      k = _char_to_num(decrypted_letters[idx - len(cleaned_key)])

    p = (c - k) % 26
    decrypted_char = _num_to_char(p)
    result[pos] = decrypted_char
    decrypted_letters.append(decrypted_char)

  return "".join(result)


def kasiski_examination(text: str, min_length: int = 3) -> dict:
  """
  卡西斯基检测 - 用于估计密钥长度

  寻找重复的三元组并计算它们之间的距离

  参数:
      text: 密文
      min_length: 最小重复长度

  返回:
      包含重复模式及其距离的字典
  """
  # 清理文本
  cleaned = "".join(c.upper() for c in text if c.isalpha())

  # 查找所有重复模式
  repeats = {}
  for length in range(min_length, min_length + 3):
    for i in range(len(cleaned) - length + 1):
      pattern = cleaned[i : i + length]
      if pattern not in repeats:
        repeats[pattern] = []
      repeats[pattern].append(i)

  # 找出有重复的模式及其距离
  result = {}
  for pattern, positions in repeats.items():
    if len(positions) > 1:
      distances = [
        positions[j] - positions[i]
        for i in range(len(positions))
        for j in range(i + 1, len(positions))
      ]
      result[pattern] = distances

  return result


def friedman_test(text: str) -> float:
  """
  弗里德曼测试 - 估计密钥长度

  基于重合指数(Index of Coincidence)

  参数:
      text: 密文

  返回:
      估计的密钥长度
  """

  # 清理文本
  cleaned = "".join(c.upper() for c in text if c.isalpha())
  n = len(cleaned)

  if n < 2:
    return 1.0

  # 计算字母频率
  freq = {}
  for c in cleaned:
    freq[c] = freq.get(c, 0) + 1

  # 计算重合指数
  ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

  # 估计密钥长度 (英语的重合指数约为0.067，随机文本约为0.038)
  english_ic = 0.0667
  random_ic = 0.0385

  if ic <= random_ic:
    return 1.0

  return (english_ic - random_ic) / (ic - random_ic)


if __name__ == "__main__":
  # 测试维吉尼亚密码
  source_text = "HELLO WORLD"
  key = "KEY"

  print(f"原文: {source_text}")
  print(f"密钥: {key}")

  encrypted = encrypt(source_text, key)
  print(f"加密后: {encrypted}")

  decrypted = decrypt(encrypted, key)
  print(f"解密后: {decrypted}")

  # 测试自动密钥密码
  print("\n--- 自动密钥密码 ---")
  auto_encrypted = autokey_encrypt(source_text, key)
  print(f"自动密钥加密: {auto_encrypted}")

  auto_decrypted = autokey_decrypt(auto_encrypted, key)
  print(f"自动密钥解密: {auto_decrypted}")

  # 测试卡西斯基检测
  print("\n--- 卡西斯基检测 ---")
  long_text = "HELLOHELLOHELLO"
  kasiski = kasiski_examination(encrypt(long_text, "SECRET"))
  print(f"卡西斯基检测结果: {kasiski}")
