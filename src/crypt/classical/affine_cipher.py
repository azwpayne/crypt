# @author  : azwpayne(https://github.com/azwpayne)
# @name    : affine_cipher.py
# @time    : 2026/3/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 仿射密码加密和解密实现


def _gcd(a: int, b: int) -> int:
  """计算最大公约数"""
  while b:
    a, b = b, a % b
  return a


def _mod_inverse(a: int, m: int) -> int | None:
  """
  计算模逆元

  参数:
      a: 需要求逆元的数
      m: 模数

  返回:
      如果存在逆元则返回逆元，否则返回None
  """
  a %= m
  return next((x for x in range(1, m) if (a * x) % m == 1), None)


def _char_to_num(char: str) -> int:
  """将大写字母转换为数字 (A=0, B=1, ..., Z=25)"""
  return ord(char.upper()) - ord("A")


def _num_to_char(num: int) -> str:
  """将数字转换为大写字母"""
  return chr((num % 26) + ord("A"))


def encrypt(text: str, a: int, b: int) -> str:
  """
  使用仿射密码加密文本

  加密公式: E(x) = (ax + b) mod 26

  参数:
      text: 待加密的字符串（只处理字母）
      a: 乘法密钥（必须与26互质）
      b: 加法密钥

  返回:
      加密后的大写字符串

  异常:
      ValueError: 如果a与26不互质
  """
  if _gcd(a, 26) != 1:
    msg = f"密钥{a=}必须与26互质"
    raise ValueError(msg)

  result = []
  for char in text:
    if char.isascii() and char.isalpha():
      x = _char_to_num(char)
      encrypted_num = (a * x + b) % 26
      result.append(_num_to_char(encrypted_num))
    else:
      result.append(char)
  return "".join(result)


def decrypt(text: str, a: int, b: int) -> str:
  """
  使用仿射密码解密文本

  解密公式: D(y) = a^(-1) * (y - b) mod 26

  参数:
      text: 待解密的字符串
      a: 乘法密钥
      b: 加法密钥

  返回:
      解密后的大写字符串

  异常:
      ValueError: 如果a与26不互质或逆元不存在
  """
  a_inv = _mod_inverse(a, 26)
  if a_inv is None:
    msg = f"密钥a={a=}在模26下没有逆元"
    raise ValueError(msg)

  result = []
  for char in text:
    if char.isascii() and char.isalpha():
      y = _char_to_num(char)
      decrypted_num = (a_inv * (y - b)) % 26
      result.append(_num_to_char(decrypted_num))
    else:
      result.append(char)
  return "".join(result)


def brute_force_decrypt(text: str) -> list[dict]:
  """
  暴力破解仿射密码

  尝试所有可能的(a, b)密钥组合（a必须与26互质）

  参数:
      text: 待解密的字符串

  返回:
      包含所有可能解密结果的列表
  """
  # 与26互质的数
  valid_a_values = [a for a in range(1, 26) if _gcd(a, 26) == 1]

  results = []
  for a in valid_a_values:
    for b in range(26):
      decrypted = decrypt(text, a, b)
      results.append({"a": a, "b": b, "text": decrypted})
  return results


def get_valid_a_values() -> list[int]:
  """
  获取所有有效的a值（与26互质的数）

  返回:
      有效的a值列表
  """
  return [a for a in range(1, 26) if _gcd(a, 26) == 1]


if __name__ == "__main__":
  # 测试仿射密码
  source_text = "HELLO"
  a_key = 5  # 必须与26互质
  b_key = 8

  print(f"原文: {source_text}")
  print(f"密钥: a={a_key}, b={b_key}")

  encrypted = encrypt(source_text, a_key, b_key)
  print(f"加密后: {encrypted}")

  decrypted = decrypt(encrypted, a_key, b_key)
  print(f"解密后: {decrypted}")

  # 测试暴力破解
  print("\n暴力破解测试（前5个结果）:")
  all_results = brute_force_decrypt(encrypted)
  for result in all_results[:5]:
    print(f"  a={result['a']}, b={result['b']}: {result['text']}")
