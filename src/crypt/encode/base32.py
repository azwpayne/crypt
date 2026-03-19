# @time    : 2026/1/10 07:14
# @name    : base32.py
# @author  : azwpayne
# @desc    :


import base64
import sys

# Base32 字母表 (RFC 4648 标准)
BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
PADDING_CHAR = "="


def base32_encode(data: bytes) -> str:
  """
  将字节数据编码为 Base32 字符串

  Args:
      data: 要编码的字节数据

  Returns:
      Base32 编码字符串
  """
  if not data:
    return ""

  # 将字节转换为二进制字符串
  binary_str = "".join(f"{byte:08b}" for byte in data)

  # 补零到5的倍数
  padding_len = (5 - len(binary_str) % 5) % 5
  binary_str += "0" * padding_len

  encoded = [
    BASE32_ALPHABET[int(binary_str[i : i + 5], 2)] for i in range(0, len(binary_str), 5)
  ]
  # 添加填充字符
  padding = (8 - len(encoded) % 8) % 8
  encoded.extend([PADDING_CHAR] * padding)

  return "".join(encoded)


def base32_decode(encoded_str: str) -> bytes:
  """
  将 Base32 字符串解码为原始字节数据

  Args:
      encoded_str: Base32 编码字符串

  Returns:
      解码后的字节数据
  """
  # 移除填充字符和空白字符
  encoded_str = encoded_str.strip().rstrip(PADDING_CHAR)
  if not encoded_str:
    return b""

  # 验证输入字符
  for char in encoded_str:
    if char not in BASE32_ALPHABET:
      msg = f"Invalid Base32 character: '{char}'"
      raise ValueError(msg)

  # 将字符转换为索引
  indices = [BASE32_ALPHABET.index(char) for char in encoded_str]

  # 将索引转换为二进制字符串
  binary_str = "".join(f"{index:05b}" for index in indices)

  # 移除可能的多余位（由填充产生）
  if len(indices) % 8 != 0:
    # 计算实际有效位数
    total_bits = (len(indices) * 5) // 8 * 8
    binary_str = binary_str[:total_bits]

  # 将二进制字符串转换为字节
  result = bytearray()
  for i in range(0, len(binary_str), 8):
    if i + 8 <= len(binary_str):
      byte_str = binary_str[i : i + 8]
      result.append(int(byte_str, 2))

  return bytes(result)


def test_base32():
  """测试 Base32 编码解码功能"""
  test_cases = [
    b"",
    b"f",
    b"fo",
    b"foo",
    b"foob",
    b"fooba",
    b"foobar",
    b"Hello, World!",  # 文本
    b"\x00\x01\x02\x03\x04\x05",  # 二进制数据
    b"A" * 10,  # 重复字符
  ]

  print("测试 Base32 实现:")
  print("-" * 50)

  def _run_test_case(i: int, test_data: bytes) -> bool:
    """Run a single test case; return True if passed."""
    try:
      encoded_custom = base32_encode(test_data)
      encoded_std = base64.b32encode(test_data).decode("ascii").rstrip("=")
      decoded_custom = base32_decode(encoded_custom)
      encode_match = "✓" if encoded_custom.rstrip("=") == encoded_std else "✗"
      decode_match = "✓" if decoded_custom == test_data else "✗"
      print(f"测试 {i + 1}:")
      print(f"  原始数据: {test_data!r}")
      print(f"  编码结果: {encoded_custom}")
      print(f"  标准库结果: {encoded_std}")
      print(f"  解码结果: {decoded_custom!r}")
      print(f"  编码匹配: {encode_match}  解码正确: {decode_match}")
      print()
    except ValueError as e:
      print(f"测试 {i + 1} 失败: {e}")
      print()
      return False
    else:
      return encode_match == "✓" and decode_match == "✓"

  all_passed = True
  for i, test_data in enumerate(test_cases):
    if not _run_test_case(i, test_data):
      all_passed = False

  # 边缘情况测试
  print("边缘情况测试:")
  print("-" * 50)

  # 测试无效字符
  try:
    base32_decode("A!BC")  # 包含无效字符 '!'
    print("无效字符测试: ✗ (应该抛出异常但没有)")
    all_passed = False
  except ValueError:
    print("无效字符测试: ✓ (正确抛出异常)")

  # 测试随机数据
  import random

  random_data = bytes(random.getrandbits(8) for _ in range(100))
  encoded = base32_encode(random_data)
  decoded = base32_decode(encoded)
  # sourcery skip: no-conditionals-in-tests
  if decoded == random_data:
    print("随机数据测试 (100字节): ✓")
  else:
    print("随机数据测试 (100字节): ✗")
    all_passed = False

  print("-" * 50)
  if all_passed:
    print("所有测试通过! ✓")
  else:
    print("部分测试失败! ✗")
    sys.exit(1)


# if __name__ == "__main__":
#   # 运行测试
#   test_base32()
#
#   # 示例用法
#   print("\n示例用法:")
#   print("-" * 50)
#
#   # 示例1: 编码字符串
#   text = "Hello, Base32!"
#   data = text.encode("utf-8")
#   encoded = base32_encode(data)
#   decoded = base32_decode(encoded)
#   decoded_text = decoded.decode("utf-8")
#
#   print("示例1 - 文本编码解码:")
#   print(f"  原始文本: {text}")
#   print(f"  Base32编码: {encoded}")
#   print(f"  解码文本: {decoded_text}")
#
#   # 示例2: 编码二进制数据
#   binary_data = b"\xde\xad\xbe\xef\xca\xfe"
#   encoded_binary = base32_encode(binary_data)
#   decoded_binary = base32_decode(encoded_binary)
#
#   print("\n示例2 - 二进制数据编码解码:")
#   print(f"  原始数据: {binary_data.hex()}")
#   print(f"  Base32编码: {encoded_binary}")
#   print(f"  解码数据: {decoded_binary.hex()}")
