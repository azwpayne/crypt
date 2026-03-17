# @author  : azwpayne(https://github.com/azwpayne)
# @name    : polybius_square.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 波利比奥斯方阵加密和解密实现


def _create_square(key: str = "", size: int = 5) -> tuple[list[list[str]], str]:
    # sourcery skip: inline-variable, switch
  """
  创建波利比奥斯方阵

  参数:
      key: 密钥（用于填充方阵的前几个位置）
      size: 方阵大小（5x5 或 6x6）

  返回:
      (方阵, 使用的字母表)
  """
  if size == 5:
    # 5x5方阵：I和J共享一个位置
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 注意没有J
  elif size == 6:
    # 6x6方阵：包含所有字母和数字0-9
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  else:
    msg = "方阵大小必须是5或6"
    raise ValueError(msg)

  # 清理密钥并去重
  seen = set()
  unique_key = []
  for c in key.upper():
      char_to_add = c
      if char_to_add == "J" and size == 5:
          char_to_add = "I"
      if char_to_add not in seen and char_to_add in alphabet:
          seen.add(char_to_add)
          unique_key.append(char_to_add)

  # 填充剩余字母
  remaining = [c for c in alphabet if c not in seen]
  full_sequence = unique_key + remaining

  # 创建方阵
  square = [full_sequence[i * size : (i + 1) * size] for i in range(size)]

  return square, alphabet


def _find_position(square: list[list[str]], char: str) -> tuple[int, int] | None:
  """
  在方阵中查找字符的位置

  返回:
      (行, 列) 或 None（如果未找到）
  """
  return next(
      ((row_idx, row.index(char)) for row_idx, row in enumerate(square) if char in row),
      None,
  )


def encrypt(
  text: str, key: str = "", size: int = 5, row_labels: str = "", col_labels: str = ""
) -> str:
  """
  使用波利比奥斯方阵加密文本

  参数:
      text: 待加密的字符串
      key: 密钥（可选）
      size: 方阵大小（5或6）
      row_labels: 行标签（默认1,2,3,...）
      col_labels: 列标签（默认1,2,3,...）

  返回:
      加密后的数字串（默认用行号和列号表示）

  示例:
      >>> encrypt("HELLO")
      '23 15 31 31 34'
  """
  square, alphabet = _create_square(key, size)

  # 设置默认标签
  if not row_labels:
    row_labels = "".join(str(i + 1) for i in range(size))
  if not col_labels:
    col_labels = "".join(str(i + 1) for i in range(size))

  result = []
  for char in text.upper():
      processed_char = char
      if processed_char == "J" and size == 5:
          processed_char = "I"

      if processed_char in alphabet:
          row, col = _find_position(square, processed_char)
      result.append(f"{row_labels[row]}{col_labels[col]}")

  return " ".join(result)


def decrypt(
  encrypted_text: str,
  key: str = "",
  size: int = 5,
  row_labels: str = "",
  col_labels: str = "",
) -> str:
  """
  使用波利比奥斯方阵解密文本

  参数:
      encrypted_text: 加密后的数字串
      key: 密钥
      size: 方阵大小
      row_labels: 行标签
      col_labels: 列标签

  返回:
      解密后的字符串
  """
  square, _ = _create_square(key, size)

  # 设置默认标签
  if not row_labels:
    row_labels = "".join(str(i + 1) for i in range(size))
  if not col_labels:
    col_labels = "".join(str(i + 1) for i in range(size))

  # 创建标签到索引的映射
  row_map = {c: i for i, c in enumerate(row_labels)}
  col_map = {c: i for i, c in enumerate(col_labels)}

  result = []
  # 分割成对
  codes = encrypted_text.replace(" ", "")

  for i in range(0, len(codes), 2):
    if i + 1 < len(codes):
      row_char = codes[i]
      col_char = codes[i + 1]

      if row_char in row_map and col_char in col_map:
        row = row_map[row_char]
        col = col_map[col_char]
        result.append(square[row][col])

  return "".join(result)


def print_square(key: str = "", size: int = 5) -> str:
  """
  打印波利比奥斯方阵

  参数:
      key: 密钥
      size: 方阵大小

  返回:
      格式化的方阵字符串
  """
  square, _ = _create_square(key, size)

  lines = ["  " + " ".join(str(i + 1) for i in range(size))]
  lines.extend(f"{i + 1} " + " ".join(row) for i, row in enumerate(square))
  return "\n".join(lines)


def encrypt_with_custom_output(text: str, key: str = "", size: int = 5) -> str:
  """
  使用波利比奥斯方阵加密，输出使用字母坐标

  使用A-E作为坐标标签

  参数:
      text: 待加密的字符串
      key: 密钥
      size: 方阵大小

  返回:
      加密后的字符串（使用字母坐标）
  """
  row_labels = "ABCDE"[:size]
  col_labels = "ABCDE"[:size]
  return encrypt(text, key, size, row_labels, col_labels)


def decrypt_with_custom_input(encrypted_text: str, key: str = "", size: int = 5) -> str:
  """
  使用字母坐标解密密文

  参数:
      encrypted_text: 加密后的字母坐标串
      key: 密钥
      size: 方阵大小

  返回:
      解密后的字符串
  """
  row_labels = "ABCDE"[:size]
  col_labels = "ABCDE"[:size]
  return decrypt(encrypted_text, key, size, row_labels, col_labels)


if __name__ == "__main__":
  # 测试波利比奥斯方阵
  print("5x5 波利比奥斯方阵:")
  print(print_square())
  print()

  source_text = "HELLO"
  print(f"原文: {source_text}")

  encrypted = encrypt(source_text)
  print(f"加密后: {encrypted}")

  decrypted = decrypt(encrypted)
  print(f"解密后: {decrypted}")

  # 使用密钥
  print("\n使用密钥 'KEYWORD':")
  print(print_square("KEYWORD"))

  encrypted_key = encrypt(source_text, "KEYWORD")
  print(f"加密: {encrypted_key}")

  decrypted_key = decrypt(encrypted_key, "KEYWORD")
  print(f"解密: {decrypted_key}")

  # 6x6方阵（包含数字）
  print("\n6x6 波利比奥斯方阵:")
  print(print_square(size=6))
