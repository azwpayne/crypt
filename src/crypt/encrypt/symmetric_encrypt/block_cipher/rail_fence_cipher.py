# @author  : azwpayne(https://github.com/azwpayne)
# @name    : rail_fence_cipher.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 栅栏密码加密和解密实现（置换密码）


def encrypt(text: str, rails: int) -> str:
  """
  使用栅栏密码加密文本

  栅栏密码将文本按锯齿形排列在多行（栅栏）上，然后按行读取

  参数:
      text: 待加密的字符串
      rails: 栅栏数（行数），必须大于等于2

  返回:
      加密后的字符串

  示例:
      >>> encrypt("HELLOWORLD", 3)
      'HOLELWRDLO'

  排列方式（3栅栏）:
      H . . . O . . . L . .
      . E . L . W . R . D .
      . . L . . . O . . . L
  """
  if rails < 1:
    msg = "栅栏数必须大于等于1"
    raise ValueError(msg)

  if rails == 1:
    return text

  if len(text) <= rails:
    return text

  # 创建栅栏
  fence = [[] for _ in range(rails)]

  # 填充栅栏（锯齿形）
  rail = 0
  direction = 1  # 1表示向下，-1表示向上

  for char in text:
    fence[rail].append(char)
    rail += direction

    # 到达边界时改变方向
    if rail == 0 or rail == rails - 1:
      direction *= -1

  # 按行读取
  return "".join("".join(row) for row in fence)


def decrypt(text: str, rails: int) -> str:
  """
  使用栅栏密码解密文本

  参数:
      text: 待解密的字符串
      rails: 栅栏数

  返回:
      解密后的字符串
  """
  if rails < 1:
    msg = "栅栏数必须大于等于1"
    raise ValueError(msg)

  if rails == 1:
    return text

  if len(text) <= rails:
    return text

  n = len(text)

  # 计算每行的长度
  # 一个完整的周期是 2*(rails-1) 个字符
  cycle = 2 * (rails - 1)

  # 计算每行应该有多少个字符
  row_lengths = [0] * rails

  for i in range(n):
    pos = i % cycle
    if pos >= rails:
      pos = cycle - pos
    row_lengths[pos] += 1

  # 分割文本到各行
  fence = []
  idx = 0
  for length in row_lengths:
    fence.append(list(text[idx : idx + length]))
    idx += length

  # 按锯齿形读取
  result = []
  rail = 0
  direction = 1

  for _ in range(n):
    result.append(fence[rail].pop(0))
    rail += direction

    if rail == 0 or rail == rails - 1:
      direction *= -1

  return "".join(result)


def _try_decrypt(text: str, rails: int) -> str | None:
  """Attempt to decrypt with a given rail count; return None on failure."""
  try:
    return decrypt(text, rails)
  except ValueError:
    return None


def brute_force_decrypt(text: str, max_rails: int = 10) -> dict[int, str]:
  """
  暴力破解栅栏密码

  尝试所有可能的栅栏数

  参数:
      text: 待解密的字符串
      max_rails: 最大尝试的栅栏数

  返回:
      包含所有可能解密结果的字典
  """
  results = {}
  for rails in range(2, min(max_rails + 1, len(text) + 1)):
    result = _try_decrypt(text, rails)
    if result is None:
      break
    results[rails] = result
  return results


def encrypt_with_offset(text: str, rails: int, offset: int) -> str:
  """
  带偏移量的栅栏密码加密

  偏移量表示起始位置在栅栏中的偏移

  参数:
      text: 待加密的字符串
      rails: 栅栏数
      offset: 起始偏移量

  返回:
      加密后的字符串
  """
  if rails < 2:
    msg = "栅栏数必须大于等于2"
    raise ValueError(msg)

  # 创建栅栏
  fence = [[] for _ in range(rails)]

  # 填充栅栏（从偏移位置开始）
  rail = offset % rails
  direction = 1 if (offset // (rails - 1)) % 2 == 0 else -1

  for char in text:
    fence[rail].append(char)
    rail += direction

    if rail == 0 or rail == rails - 1:
      direction *= -1

  return "".join("".join(row) for row in fence)


def print_fence(text: str, rails: int) -> str:
  """
  可视化栅栏排列

  参数:
      text: 待显示的字符串
      rails: 栅栏数

  返回:
      可视化字符串
  """
  if len(text) > 50:  # 太长的文本不显示
    return "文本太长，无法可视化"

  # 创建栅栏矩阵
  n = len(text)
  matrix = [[" " for _ in range(n)] for _ in range(rails)]

  rail = 0
  direction = 1

  for col, char in enumerate(text):
    matrix[rail][col] = char
    rail += direction

    if rail in [0, rails - 1]:
      direction *= -1

  # 格式化输出
  lines = [" ".join(row) for row in matrix]

  return "\n".join(lines)


if __name__ == "__main__":
  # 测试栅栏密码
  source_text = "HELLOWORLD"
  rails = 3

  print(f"原文: {source_text}")
  print(f"栅栏数: {rails}")
  print("\n栅栏可视化:")
  print(print_fence(source_text, rails))

  encrypted = encrypt(source_text, rails)
  print(f"\n加密后: {encrypted}")

  decrypted = decrypt(encrypted, rails)
  print(f"解密后: {decrypted}")

  # 测试暴力破解
  print("\n--- 暴力破解测试 ---")
  all_results = brute_force_decrypt(encrypted, max_rails=5)
  for r, result in all_results.items():
    marker = " <--" if result == source_text else ""
    print(f"栅栏数 {r}: {result}{marker}")
