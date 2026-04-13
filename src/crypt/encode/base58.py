# @time    : 2026/1/10 08:02
# @name    : base58.py
# @author  : azwpayne
# @desc    :

# Base58字符集 (排除容易混淆的字符：0, O, I, l)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_BASE = len(BASE58_ALPHABET)
BASE58_MAP = {c: i for i, c in enumerate(BASE58_ALPHABET)}


def encode_base58(data: bytes) -> str:
  """
  将字节数据编码为Base58字符串

  Args:
      data: 要编码的字节数据

  Returns:
      Base58编码的字符串
  """
  # 统计前导零的数量
  leading_zeros = 0
  for byte in data:
    if byte == 0:
      leading_zeros += 1
    else:
      break

  # 将字节转换为大整数
  num = 0
  for byte in data:
    num = num * 256 + byte

  # 将大整数转换为Base58
  encoded = []
  while num > 0:
    num, remainder = divmod(num, BASE58_BASE)
    encoded.append(BASE58_ALPHABET[remainder])

  # 反转结果并添加前导'1'（对应零字节）
  encoded_str = "".join(reversed(encoded))

  return "1" * leading_zeros + encoded_str  # Empty input returns empty string


def decode_base58(encoded: str) -> bytes:
  """
  将Base58字符串解码为字节数据

  Args:
      encoded: Base58编码的字符串

  Returns:
      解码后的字节数据
  """
  # 统计前导'1'的数量（对应零字节）
  leading_ones = 0
  for char in encoded:
    if char == "1":
      leading_ones += 1
    else:
      break

  # 将Base58转换为大整数
  num = 0
  for char in encoded:
    if char not in BASE58_MAP:
      msg = f"无效的Base58字符: '{char}'"
      raise ValueError(msg)
    num = num * BASE58_BASE + BASE58_MAP[char]

  # 将大整数转换为字节
  decoded = []
  while num > 0:
    num, byte = divmod(num, 256)
    decoded.append(byte)

  # 反转结果并添加前导零
  decoded_bytes = bytes(reversed(decoded))

  return b"\x00" * leading_ones + decoded_bytes


def encode_base58_check(data: bytes, checksum_len: int = 4) -> str:
  """
  添加校验和的Base58编码（如比特币地址使用）

  Args:
      data: 要编码的字节数据
      checksum_len: 校验和长度（通常为4字节）

  Returns:
      带校验和的Base58编码字符串
  """
  import hashlib

  # 计算双SHA256哈希作为校验和
  hash1 = hashlib.sha256(data).digest()
  hash2 = hashlib.sha256(hash1).digest()
  checksum = hash2[:checksum_len]

  # 将数据和校验和拼接
  data_with_checksum = data + checksum

  return encode_base58(data_with_checksum)


def decode_base58_check(encoded: str, checksum_len: int = 4) -> bytes:
  """
  解码带校验和的Base58字符串

  Args:
      encoded: Base58编码的字符串
      checksum_len: 校验和长度（通常为4字节）

  Returns:
      解码后的字节数据（不包含校验和）

  Raises:
      ValueError: 校验和验证失败
  """
  import hashlib

  # 解码Base58
  decoded = decode_base58(encoded)

  if len(decoded) < checksum_len:
    msg = "Base58Check数据太短"
    raise ValueError(msg)

  # 分离数据和校验和
  data = decoded[:-checksum_len]
  checksum = decoded[-checksum_len:]

  # 重新计算校验和
  hash1 = hashlib.sha256(data).digest()
  hash2 = hashlib.sha256(hash1).digest()
  expected_checksum = hash2[:checksum_len]

  # 验证校验和
  if checksum != expected_checksum:
    msg = "Base58Check校验和验证失败"
    raise ValueError(msg)

  return data


# 测试函数
def test_base58():
  """测试Base58编码/解码"""
  test_cases = [
    b"",  # 空数据
    b"\x00",  # 单个零
    b"\x00\x00",  # 两个零
    b"Hello World!",  # 文本
    b"\xff\xff\xff\xff",  # 全FF
    b"\x00\x01\x02\x03\x04\x05",  # 递增序列
  ]

  print("测试Base58编码/解码:")
  print("-" * 60)

  for i, data in enumerate(test_cases):
    encoded = encode_base58(data)
    decoded = decode_base58(encoded)

    status = "✓" if decoded == data else "✗"
    print(f"测试 {i + 1}: {status}")
    print(f"  原始: {data.hex() or '(空)'}")
    print(f"  编码: {encoded}")
    print(f"  解码: {decoded.hex() or '(空)'}")
    print()

  # 测试Base58Check
  print("测试Base58Check:")
  print("-" * 60)

  data = b"Test data for checksum"
  test_encoded_check = encode_base58_check(data)
  test_decoded_check = decode_base58_check(test_encoded_check)

  status = "✓" if test_decoded_check == data else "✗"
  print(f"Base58Check测试: {status}")
  print(f"  原始: {data.hex()}")
  print(f"  编码: {test_encoded_check}")
  print(f"  解码: {test_decoded_check.hex()}")

  # 测试错误校验和
  try:
    # 修改最后一个字符来破坏校验和
    corrupted = test_encoded_check[:-1] + (
      "2" if test_encoded_check[-1] == "1" else "1"
    )
    decode_base58_check(corrupted)
    print("\n校验和测试: ✗ (应该失败但没有失败)")
  except ValueError as e:
    print(f"\n校验和测试: ✓ 正确捕获错误: {e}")


# 示例使用
if __name__ == "__main__":
  # 基本用法示例
  test_data = b"Hello Bitcoin!"

  # 基本Base58编码
  test_encoded = encode_base58(test_data)
  print(f"原始数据: {test_data!r}")
  print(f"Base58编码: {test_encoded}")

  # 基本Base58解码
  test_decoded = decode_base58(test_encoded)
  print(f"Base58解码: {test_decoded!r}")
  print(f"数据匹配: {test_data == test_decoded}")
  print()

  # Base58Check编码（带校验和）
  encoded_check = encode_base58_check(test_data)
  print(f"Base58Check编码: {encoded_check}")

  # Base58Check解码
  decoded_check = decode_base58_check(encoded_check)
  print(f"Base58Check解码: {decoded_check!r}")
  print(f"数据匹配: {test_data == decoded_check}")

  # 运行完整测试
  test_base58()
