# @time    : 2026/1/10 08:03
# @name    : base91.py
# @author  : azwpayne
# @desc    :
BASE91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
DECODING_TABLE = {char: idx for idx, char in enumerate(BASE91_ALPHABET)}


def base91_encode(inp: bytes) -> str:
  """
  将字节数据编码为 base91 字符串

  Args:
      inp: 要编码的字节数据

  Returns:
      base91 编码字符串
  """
  b = 0
  n = 0
  out: list[str] = []

  for byte in inp:
    b |= byte << n
    n += 8
    if n > 13:  # 至少有 14 位
      v = b & 8191  # 8191 = 2^13 - 1
      if v > 88:
        b >>= 13
        n -= 13
      else:
        v = b & 16383  # 16383 = 2^14 - 1
        b >>= 14
        n -= 14
      out.extend((BASE91_ALPHABET[v % 91], BASE91_ALPHABET[v // 91]))
  if n:
    out.append(BASE91_ALPHABET[b % 91])
    if n > 7 or b > 90:
      out.append(BASE91_ALPHABET[b // 91])

  return "".join(out)


def base91_decode(inp: str) -> bytes:
  """
  将 base91 字符串解码为字节数据

  Args:
      inp: base91 编码字符串

  Returns:
      解码后的字节数据
  """
  v = -1
  b = 0
  n = 0
  out = bytearray()

  for char in inp:
    if char not in DECODING_TABLE:
      continue
    c = DECODING_TABLE[char]
    if v < 0:
      v = c
    else:
      v += c * 91
      b |= v << n
      n += 13 if (v & 8191) > 88 else 14
      while n > 7:
        out.append(b & 0xFF)
        b >>= 8
        n -= 8
      v = -1

  if v != -1:
    b |= v << n
    out.append(b & 0xFF)

  return bytes(out)


def base91_encode_str(inp: str, encoding: str = "utf-8") -> str:
  """
  将字符串编码为 base91 字符串

  Args:
      inp: 要编码的文本
      encoding: 文本编码方式

  Returns:
      base91 编码字符串
  """
  return base91_encode(inp.encode(encoding))


def base91_decode_str(inp: str, encoding: str = "utf-8") -> str:
  """
  将 base91 字符串解码为原始字符串

  Args:
      inp: base91 编码字符串
      encoding: 文本编码方式

  Returns:
      解码后的原始字符串
  """
  return base91_decode(inp).decode(encoding)


# 使用示例
if __name__ == "__main__":

  def _extracted_from_test_base91_21(arg0, arg1, arg2):
    print(f"Original: {arg0!r}")
    print(f"Encoded:  {arg1}")
    print(f"Decoded:  {arg2!r}")
    print(f"Match:    {arg0 == arg2}")

  def test_base91():
    """测试 base91 编码解码"""
    test_cases = [
      b"Hello, World!",
      b"Python 3",
      b"1234567890",
      b"",
      b"A" * 10,
      b"\x00\x01\x02\x03\x04\x05",
      b"Base91 encoding test with some special characters: !@#$%^&*()",
    ]

    print("Testing Base91 encode/decode:")
    print("=" * 60)

    for i, test_data in enumerate(test_cases, 1):
      encoded_result = base91_encode(test_data)
      decoded_result = base91_decode(encoded_result)

      print(f"\nTest {i}:")
      _extracted_from_test_base91_21(test_data, encoded_result, decoded_result)
    # 测试字符串版本
    print("\n" + "=" * 60)
    print("Testing string encode/decode:")
    test_str = "Hello, 世界! 🌍"
    encoded_str = base91_encode_str(test_str)
    decoded_str = base91_decode_str(encoded_str)
    _extracted_from_test_base91_21(test_str, encoded_str, decoded_str)

  # 基本使用
  data = b"Hello, Base91!"
  encoded = base91_encode(data)
  decoded = base91_decode(encoded)

  print(f"Original: {data!r}")
  print(f"Encoded:  {encoded}")
  print(f"Decoded:  {decoded!r}")
  print(f"Match:    {data == decoded}")

  # 字符串版本
  text = "Hello, 世界!"
  encoded_text = base91_encode_str(text)
  decoded_text = base91_decode_str(encoded_text)

  print(f"\nText Original: {text}")
  print(f"Text Encoded:  {encoded_text}")
  print(f"Text Decoded:  {decoded_text}")
  print(f"Match:         {text == decoded_text}")

  # 运行测试
  print("\n" + "=" * 60)
  test_base91()
