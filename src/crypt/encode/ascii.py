# @time    : 2026/1/6 13:31
# @name    : ascii.py
# @author  : azwpayne
# @desc    :


def ascii_encode(data: str) -> list[int]:
  """
  将字符串编码为 ASCII 码列表

  :param data: 输入字符串
  :return: ASCII 码整数列表
  :raises ValueError: 当包含非 ASCII 字符时

  示例:
      >>> ascii_encode("Hello")
      [72, 101, 108, 108, 111]
      >>> ascii_encode("")
      []
  """
  if not isinstance(data, str):
    msg = "输入必须是字符串"
    raise TypeError(msg)

  if not data:
    return []

  result = []
  for character in data:
    code = ord(character)
    if code > 127:
      msg = f"包含非 ASCII 字符 '{character}' (Unicode: U+{code:04X})"
      raise ValueError(msg)
    result.append(code)

  return result


def ascii_decode(ascii_codes: list[int]) -> str:
  """
  将 ASCII 码列表解码为字符串

  :param ascii_codes: ASCII 码整数列表
  :return: 解码后的字符串
  :raises ValueError: 当包含无效 ASCII 码时

  示例:
      >>> ascii_decode([72, 101, 108, 108, 111])
      'Hello'
      >>> ascii_decode([])
      ''
  """
  if not isinstance(ascii_codes, list):
    msg = "输入必须是列表"
    raise TypeError(msg)

  if not ascii_codes:
    return ""

  result = []
  for code in ascii_codes:
    if not isinstance(code, int):
      msg = f"ASCII 码必须是整数,得到: {type(code)}"
      raise TypeError(msg)
    if code < 0 or code > 127:
      msg = f"无效的 ASCII 码: {code} (必须在 0-127 范围内)"
      raise ValueError(msg)
    result.append(chr(code))

  return "".join(result)


def ascii_encode_hex(data: str) -> str:
  """
  将字符串编码为十六进制格式的 ASCII 码

  :param data: 输入字符串
  :return: 十六进制字符串（大写，不含前缀）
  :raises ValueError: 当包含非 ASCII 字符时

  示例:
      >>> ascii_encode_hex("Hello")
      '48656C6C6F'
      >>> ascii_encode_hex("")
      ''
  """
  codes = ascii_encode(data)
  return "".join(f"{code:02X}" for code in codes)


def ascii_decode_hex(hex_str: str) -> str:
  """
  从十六进制格式的 ASCII 码解码为字符串

  :param hex_str: 十六进制字符串（可含 0x 前缀或空格）
  :return: 解码后的字符串
  :raises ValueError: 当格式无效或包含非 ASCII 码时

  示例:
      >>> ascii_decode_hex("48656C6C6F")
      'Hello'
      >>> ascii_decode_hex("0x48 0x65 0x6C 0x6C 0x6F")
      'Hello'
      >>> ascii_decode_hex("")
      ''
  """
  if not hex_str:
    return ""

  # 清理输入: 移除前缀、空格和换行符
  clean_hex = hex_str.replace("0x", "").replace(" ", "").replace("\n", "").strip()

  if not clean_hex:
    return ""

  # 验证十六进制有效性
  try:
    int(clean_hex, 16)
  except ValueError as exp:
    msg = f"无效的十六进制字符串 {hex_str}"
    raise ValueError(msg) from exp

  # 确保长度为偶数
  if len(clean_hex) % 2 != 0:
    clean_hex = f"0{clean_hex}"

  # 每两个十六进制字符转为一个 ASCII 码
  ascii_codes = []
  for i in range(0, len(clean_hex), 2):
    code = int(clean_hex[i : i + 2], 16)
    if code > 127:
      msg = f"超出 ASCII 范围的值 0x{clean_hex[i : i + 2]}"
      raise ValueError(msg)
    ascii_codes.append(code)

  return ascii_decode(ascii_codes)


def ascii_encode_binary(data: str) -> str:
  """
  将字符串编码为二进制字符串格式（每字节 8 位，用空格分隔）

  :param data: 输入字符串
  :return: 二进制字符串（每组 8 位，空格分隔）
  :raises ValueError: 当包含非 ASCII 字符时

  示例:
      >>> ascii_encode_binary("Hi")
      '01001000 01101001'
      >>> ascii_encode_binary("")
      ''
  """
  codes = ascii_encode(data)
  return " ".join(f"{code:08b}" for code in codes)


def ascii_decode_binary(bin_str: str) -> str:
  """
  从二进制字符串格式解码为字符串

  :param bin_str: 二进制字符串（可含空格）
  :return: 解码后的字符串
  :raises ValueError: 当格式无效或包含非 ASCII 码时

  示例:
      >>> ascii_decode_binary("01001000 01101001")
      'Hi'
      >>> ascii_decode_binary("0100100001101001")
      'Hi'
      >>> ascii_decode_binary("")
      ''
  """
  if not bin_str:
    return ""

  # 移除空格
  clean_bin = bin_str.replace(" ", "").strip()

  if not clean_bin:
    return ""

  # 验证二进制有效性
  if any(c not in "01" for c in clean_bin):
    msg = f"无效的二进制字符串: {bin_str}"
    raise ValueError(msg)

  # 确保长度是 8 的倍数
  if len(clean_bin) % 8 != 0:
    clean_bin = clean_bin.zfill(len(clean_bin) + (8 - len(clean_bin) % 8))

  # 每 8 位转为一个 ASCII 码
  ascii_codes = []
  for i in range(0, len(clean_bin), 8):
    byte = clean_bin[i : i + 8]
    code = int(byte, 2)
    if code > 127:
      msg = f"超出 ASCII 范围的值 {byte}"
      raise ValueError(msg)
    ascii_codes.append(code)

  return ascii_decode(ascii_codes)


def is_ascii_char(character: str) -> bool:
  """
  判断单个字符是否为 ASCII 字符

  :param character: 单个字符
  :return: True 如果是 ASCII 字符

  示例:
      >>> is_ascii_char('A')
      True
      >>> is_ascii_char('中')
      False
  """
  if not isinstance(character, str) or len(character) != 1:
    msg = "输入必须是单个字符"
    raise TypeError(msg)

  return ord(character) < 128


def is_ascii_string(text_str: str) -> bool:
  """
  判断字符串是否全部由 ASCII 字符组成

  :param text_str: 字符串
  :return: True 如果全部是 ASCII 字符

  示例:
      >>> is_ascii_string("Hello")
      True
      >>> is_ascii_string("你好")
      False
  """
  if not isinstance(text_str, str):
    msg = "输入必须是字符串"
    raise TypeError(msg)

  return all(ord(character) < 128 for character in text_str)


def ascii_printable_range() -> tuple[int, int]:
  """
  返回可打印 ASCII 字符的范围

  :return: (起始码，结束码) 元组

  示例:
      >>> ascii_printable_range()
      (32, 126)
  """
  return 32, 126


def is_ascii_printable(character: str) -> bool:
  """
  判断字符是否为可打印的 ASCII 字符

  :param character: 单个字符
  :return: True 如果是可打印 ASCII 字符

  示例:
      >>> is_ascii_printable('A')
      True
      >>> is_ascii_printable('\\n')
      False
  """
  if not isinstance(character, str) or len(character) != 1:
    msg = "输入必须是单个字符"
    raise TypeError(msg)

  code = ord(character)
  return 32 <= code <= 126  # noqa: PLR2004


if __name__ == "__main__":
  # 测试用例
  test_cases = [
    "Hello",
    "World",
    "Python",
    "ASCII",
    "A",
    "",
    "The quick brown fox jumps over the lazy dog",
    "!@#$%^&*()",
    "1234567890",
  ]

  for test in test_cases:
    encoded = ascii_encode(test)
    decoded = ascii_decode(encoded)
    print(f"原文: {test!r}")
    print(f"ASCII 码: {encoded}")
    print(f"解码: {decoded!r}")
    print(f"验证: {test == decoded}\n")

  print("========== ASCII 十六进制格式测试 ==========")
  hex_test_cases = ["Hello", "World", "ABC"]
  for test in hex_test_cases:
    encoded_hex = ascii_encode_hex(test)
    decoded_from_hex = ascii_decode_hex(encoded_hex)
    print(f"原文: {test!r}")
    print(f"十六进制: {encoded_hex}")
    print(f"解码: {decoded_from_hex!r}")
    print(f"验证: {test == decoded_from_hex}\n")

  # 测试带空格和前缀的十六进制
  print("========== 带格式的十六进制测试 ==========")
  formatted_hex = "0x48 0x65 0x6C 0x6C 0x6F"
  decoded_formatted = ascii_decode_hex(formatted_hex)
  print(f"格式化十六进制: {formatted_hex}")
  print(f"解码: {decoded_formatted!r}")
  print(f"验证: {decoded_formatted == 'Hello'}\n")

  print("========== ASCII 二进制格式测试 ==========")
  bin_test_cases = ["Hi", "OK"]
  for test in bin_test_cases:
    encoded_bin = ascii_encode_binary(test)
    decoded_from_bin = ascii_decode_binary(encoded_bin)
    print(f"原文: {test!r}")
    print(f"二进制: {encoded_bin}")
    print(f"解码: {decoded_from_bin!r}")
    print(f"验证: {test == decoded_from_bin}\n")

  # 测试无空格二进制
  print("========== 无空格二进制测试 ==========")
  compact_bin = "0100100001101001"
  decoded_compact = ascii_decode_binary(compact_bin)
  print(f"紧凑二进制: {compact_bin}")
  print(f"解码: {decoded_compact!r}")
  print(f"验证: {decoded_compact == 'Hi'}\n")

  print("========== ASCII 字符检测测试 ==========")
  char_tests = ["A", "中", "~", "\n", " "]
  for char in char_tests:
    is_ascii = is_ascii_char(char)
    is_printable = is_ascii_printable(char) if is_ascii else False
    print(f"字符: {char!r}, ASCII: {is_ascii}, 可打印: {is_printable}")

  print("========== ASCII 字符串检测测试 ==========")
  string_tests = ["Hello", "你好", "Hello123", "Hello 世界"]
  for text in string_tests:
    is_ascii_str = is_ascii_string(text)
    print(f"字符串: {text!r}, 全 ASCII: {is_ascii_str}")

  print("========== 异常处理测试 ==========")
  # 测试非 ASCII 字符
  try:
    ascii_encode("你好")
  except ValueError as e:
    print(f"捕获异常: {e}")

  # 测试无效 ASCII 码
  try:
    ascii_decode([200])
  except ValueError as e:
    print(f"捕获异常: {e}")

  # 测试类型错误
  try:
    ascii_encode(123)  # type: ignore[arg-type]
  except TypeError as e:
    print(f"捕获异常: {e}")

  print("========== 可打印 ASCII 范围 ==========")
  start, end = ascii_printable_range()
  print(f"可打印 ASCII 范围: {start} - {end}")
  print(f"对应字符: '{chr(start)}' - '{chr(end)}'")
