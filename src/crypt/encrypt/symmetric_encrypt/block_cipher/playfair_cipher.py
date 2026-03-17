# @author  : azwpayne(https://github.com/azwpayne)
# @name    : playfair_cipher.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Playfair密码加密和解密实现


def _create_matrix(key: str) -> list[list[str]]:
  """
  创建5x5 Playfair矩阵

  I和J共享一个位置（通常用I表示）

  参数:
      key: 密钥

  返回:
      5x5矩阵
  """
  # Playfair使用25个字母（I/J合并）
  alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 注意没有J

  # 清理密钥：去重、转大写、J替换为I
  seen = set()
  cleaned_key = []
  for c in key.upper():
    if c == "J":
      c = "I"
    if c.isalpha() and c not in seen:
      seen.add(c)
      cleaned_key.append(c)

  # 填充剩余字母
  for c in alphabet:
    if c not in seen:
      cleaned_key.append(c)

  # 创建5x5矩阵
  return [cleaned_key[i * 5 : (i + 1) * 5] for i in range(5)]


def _find_position(matrix: list[list[str]], char: str) -> tuple[int, int]:
  """
  在矩阵中查找字符的位置

  参数:
      matrix: 5x5矩阵
      char: 要查找的字符

  返回:
      (行, 列)
  """
  if char == "J":
    char = "I"

  for row_idx, row in enumerate(matrix):
    if char in row:
      return (row_idx, row.index(char))

  msg = f"字符 '{char}' 不在矩阵中"
  raise ValueError(msg)


def _prepare_text(text: str) -> list[str]:
  """
  准备明文：分组、处理重复字母、填充

  规则：
  1. 将文本分成双字母组
  2. 如果双字母组中有相同字母，在中间插入'X'
  3. 如果文本长度为奇数，末尾添加'X'

  参数:
      text: 原始文本

  返回:
      双字母组列表
  """
  # 清理文本：只保留字母，转大写，J替换为I
  cleaned = []
  for c in text.upper():
    if c.isalpha():
      if c == "J":
        c = "I"
      cleaned.append(c)

  # 处理双字母组
  digraphs = []
  i = 0
  while i < len(cleaned):
    if i == len(cleaned) - 1:
      # 奇数长度，末尾加X
      digraphs.append(cleaned[i] + "X")
      i += 1
    elif cleaned[i] == cleaned[i + 1]:
      # 相同字母，中间加X
      digraphs.append(cleaned[i] + "X")
      i += 1
    else:
      # 正常双字母组
      digraphs.append(cleaned[i] + cleaned[i + 1])
      i += 2

  return digraphs


def encrypt(text: str, key: str) -> str:
  """
  使用Playfair密码加密文本

  加密规则：
  1. 同一行：每个字母替换为右侧的字母（循环）
  2. 同一列：每个字母替换为下方的字母（循环）
  3. 不同行不同列：形成矩形，替换为同行对角位置的字母

  参数:
      text: 待加密的字符串
      key: 密钥

  返回:
      加密后的字符串

  示例:
      >>> encrypt("HELLO", "KEYWORD")
      'GYIZSC'
  """
  matrix = _create_matrix(key)
  digraphs = _prepare_text(text)

  result = []
  for digraph in digraphs:
    row1, col1 = _find_position(matrix, digraph[0])
    row2, col2 = _find_position(matrix, digraph[1])

    if row1 == row2:
      # 同一行：右移
      result.append(matrix[row1][(col1 + 1) % 5])
      result.append(matrix[row2][(col2 + 1) % 5])
    elif col1 == col2:
      # 同一列：下移
      result.append(matrix[(row1 + 1) % 5][col1])
      result.append(matrix[(row2 + 1) % 5][col2])
    else:
      # 矩形：取对角
      result.append(matrix[row1][col2])
      result.append(matrix[row2][col1])

  return "".join(result)


def decrypt(encrypted_text: str, key: str) -> str:
  """
  使用Playfair密码解密文本

  解密规则：
  1. 同一行：每个字母替换为左侧的字母（循环）
  2. 同一列：每个字母替换为上方的字母（循环）
  3. 不同行不同列：形成矩形，替换为同行对角位置的字母

  参数:
      encrypted_text: 待解密的字符串
      key: 密钥

  返回:
      解密后的字符串
  """
  matrix = _create_matrix(key)

  # 将密文分成双字母组
  cleaned = [c for c in encrypted_text.upper() if c.isalpha()]
  digraphs = [cleaned[i] + cleaned[i + 1] for i in range(0, len(cleaned), 2)]

  result = []
  for digraph in digraphs:
    row1, col1 = _find_position(matrix, digraph[0])
    row2, col2 = _find_position(matrix, digraph[1])

    if row1 == row2:
      # 同一行：左移
      result.append(matrix[row1][(col1 - 1) % 5])
      result.append(matrix[row2][(col2 - 1) % 5])
    elif col1 == col2:
      # 同一列：上移
      result.append(matrix[(row1 - 1) % 5][col1])
      result.append(matrix[(row2 - 1) % 5][col2])
    else:
      # 矩形：取对角
      result.append(matrix[row1][col2])
      result.append(matrix[row2][col1])

  return "".join(result)


def print_matrix(key: str) -> str:
  """
  打印Playfair矩阵

  参数:
      key: 密钥

  返回:
      格式化的矩阵字符串
  """
  matrix = _create_matrix(key)
  return "\n".join(" ".join(row) for row in matrix)


if __name__ == "__main__":
  # 测试Playfair密码
  key = "KEYWORD"
  source_text = "HELLO WORLD"

  print(f"密钥: {key}")
  print("Playfair矩阵:")
  print(print_matrix(key))
  print()

  print(f"原文: {source_text}")

  encrypted = encrypt(source_text, key)
  print(f"加密后: {encrypted}")

  decrypted = decrypt(encrypted, key)
  print(f"解密后: {decrypted}")

  # 更多测试用例
  test_cases = [
    ("HELLO", "SECRET"),
    ("MEET ME AT THE PARK", "MONARCHY"),
    ("BALLOON", "PLAYFAIR"),
  ]

  print("\n更多测试:")
  print("=" * 50)
  for text, test_key in test_cases:
    enc = encrypt(text, test_key)
    dec = decrypt(enc, test_key)
    print(f"原文: {text}")
    print(f"密钥: {test_key}")
    print(f"加密: {enc}")
    print(f"解密: {dec}")
    print()
