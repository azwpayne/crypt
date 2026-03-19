# @time    : 2026/1/10 07:41
# @name    : base16.py
# @author  : azwpayne
# @desc    :


def base16_encode(data: bytes, *, uppercase: bool = True) -> str:
  """
  将字节数据编码为 base16（十六进制）字符串

  Args:
      data: 要编码的字节数据
      uppercase: 是否使用大写字母（默认 True）

  Returns:
      十六进制字符串
  """
  # 十六进制字符表
  hex_chars = "0123456789ABCDEF" if uppercase else "0123456789abcdef"

  # result = []
  # for byte in data:
  #     # 取出高 4 位和低 4 位
  #     high_nibble = (byte >> 4) & 0x0F
  #     low_nibble = byte & 0x0F
  #
  #     # 映射到十六进制字符
  #     result.append(hex_chars[high_nibble])
  #     result.append(hex_chars[low_nibble])

  # 使用列表推导式生成十六进制字符序列
  result = [hex_chars[(byte >> 4) & 0x0F] + hex_chars[byte & 0x0F] for byte in data]

  # 将所有字符对连接成最终字符串
  return "".join(result)


def base16_decode(s: str) -> bytes:
  """
  将 base16（十六进制）字符串解码为字节数据

  Args:
      s: 十六进制字符串

  Returns:
      解码后的字节数据

  Raises:
      ValueError: 如果输入字符串包含非法字符或长度为奇数
  """
  # 移除空白字符
  s = s.strip().replace(" ", "").replace("\n", "").replace("\r", "")

  # 检查长度是否为偶数
  if len(s) % 2 != 0:
    message = "输入字符串长度必须为偶数"
    raise ValueError(message)

  # 创建字符到数值的映射表
  hex_to_val = {}
  for i, c in enumerate("0123456789ABCDEF"):
    hex_to_val[c] = i
    hex_to_val[c.lower()] = i

  result = bytearray()
  # 每两个字符一组处理
  for i in range(0, len(s), 2):
    char1 = s[i]
    char2 = s[i + 1]

    # 检查字符是否有效
    if char1 not in hex_to_val or char2 not in hex_to_val:
      message = f"非法十六进制字符: '{char1}' 或 '{char2}'"
      raise ValueError(message)

    # 组合成一个字节
    byte_val = (hex_to_val[char1] << 4) | hex_to_val[char2]
    result.append(byte_val)

  return bytes(result)


# ========== 使用示例 ==========

if __name__ == "__main__":
  # 测试数据
  original_data = b"Hello, World! 123"
  print(f"原始数据: {original_data}")

  # 编码（大写）
  encoded_upper = base16_encode(original_data)
  print(f"编码结果(大写): {encoded_upper}")

  # 编码（小写）
  encoded_lower = base16_encode(original_data, uppercase=False)
  print(f"编码结果(小写): {encoded_lower}")

  # 解码
  decoded_data = base16_decode(encoded_upper)
  print(f"解码结果: {decoded_data}")

  if original_data != decoded_data:
    msg = "编解码不匹配"
    raise AssertionError(msg)

  # 解码小写
  decoded_lower = base16_decode(encoded_lower)
  if original_data != decoded_lower:
    msg = "小写编解码不匹配"
    raise AssertionError(msg)

  # 测试带空格的输入
  spaced_hex = "48 65 6C 6C 6F"
  decoded_spaced = base16_decode(spaced_hex)
  print(f"带空格解码: {decoded_spaced}")

  # 测试错误处理
  try:
    base16_decode("123")  # 奇数长度
  except ValueError as e:
    print(f"错误捕获: {e}")

  try:
    base16_decode("GGGG")  # 非法字符
  except ValueError as e:
    print(f"错误捕获: {e}")
