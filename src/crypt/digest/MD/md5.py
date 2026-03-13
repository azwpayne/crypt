# @time    : 2025/12/24 13:32
# @name    : md5.py
# @author  : azwpayne
# @desc    :


import struct


def left_rotate(x, amount):
  """
  对32位无符号整数执行左循环移位操作

  :param Union[int, 'UInt32'] x: 输入的32位无符号整数 (0-0xFFFFFFFF 范围内)
  :param Union[int, 'UInt32'] amount: 左移的位数 (通常为 0-31)
  :return: 左循环移位后的32位无符号整数
  :rtype: Union[int, 'UInt32']
  """
  return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


def bitwise_choice(mask: int, if_true: int, if_false: int) -> int:
  """
  位级多路选择器 (Bitwise Multiplexer).

  根据掩码 mask 的每一位，从 if_true 或 if_false 中选择对应的位。
  对于每一位 i:
  - 如果 mask 的第 i 位为 1, 结果的第 i 位取自 if_true。
  - 如果 mask 的第 i 位为 0, 结果的第 i 位取自 if_false。

  等价于逻辑表达式：(mask & if_true) | (~mask & if_false)
  优化为异或表达式以避免 Python 中 ~ 运算符产生的负数混淆。

  Args:
      mask (int): 选择掩码 (Selection mask).
      if_true (int): 当掩码位为 1 时的源值.
      if_false (int): 当掩码位为 0 时的源值.

  Returns:
      int: 选择后的结果.
  """
  return if_false ^ (mask & (if_true ^ if_false))


def bitwise_majority(x, y, z):
  """
  位级多数函数 (Bitwise Majority Function).

  对于输入的三个整数的每一位，计算多数位值。
  对于每一位 i:
  - 如果 x, y, z 中至少有两个的第 i 位为 1, 结果的第 i 位为 1。
  - 否则，结果的第 i 位为 0。

  逻辑表达式：(x & y) | (x & z) | (y & z)
  该函数在 MD5 的 Round 2 (GG 函数) 中使用。

  Args:
      x (int): 第一个输入值 (32 位无符号整数).
      y (int): 第二个输入值 (32 位无符号整数).
      z (int): 第三个输入值 (32 位无符号整数).

  Returns:
      int: 多数运算的结果 (32 位无符号整数).
  """
  return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF


def bitwise_xor3(x, y, z):
  """
  位级异或函数 (Bitwise XOR).

  对于输入的三个整数的每一位，计算异或位值。
  对于每一位 i:
  - 如果 x, y, z 中有奇数个的第 i 位为 1, 结果的第 i 位为 1。
  - 否则，结果的第 i 位为 0。

  逻辑表达式：x ^ y ^ z
  该函数在 MD5 的 Round 3 (HH 函数) 中使用。

  Args:
      x (int): 第1个输入值 (32 位无符号整数).
      y (int): 第2个输入值 (32 位无符号整数).
      z (int): 第3个输入值 (32 位无符号整数).

  Returns:
      int: 异或运算的结果 (32 位无符号整数).
  """
  return (x ^ y ^ z) & 0xFFFFFFFF


def bitwise_nor_mix(x, y, z):
  """
  位级非异或函数 (Bitwise NOR-like).

  对于输入的三个整数的每一位：
  结果 = y ^ (x | ~z)

  逻辑表达式：y ^ (x | ~z)
  该函数在 MD5 的 Round 4 (II 函数) 中使用。

  Args:
      x (int): 第1个输入值 (32 位无符号整数).
      y (int): 第2个输入值 (32 位无符号整数).
      z (int): 第3个输入值 (32 位无符号整数).

  Returns:
      int: 运算结果 (32 位无符号整数).
  """
  return (y ^ (x | (0xFFFFFFFF ^ z))) & 0xFFFFFFFF


def FF(a, b, c, d, x, s, ac):
  a = (a + bitwise_choice(b, c, d) + x + ac) & 0xFFFFFFFF
  return left_rotate(a, s) + b & 0xFFFFFFFF


def GG(a, b, c, d, x, s, ac):
  # MD5 G function: G(X,Y,Z) = (X & Z) | (Y & ~Z)
  g = ((b & d) | (c & (0xFFFFFFFF ^ d))) & 0xFFFFFFFF
  a = (a + g + x + ac) & 0xFFFFFFFF
  return left_rotate(a, s) + b & 0xFFFFFFFF


def HH(a, b, c, d, x, s, ac):
  a = (a + bitwise_xor3(b, c, d) + x + ac) & 0xFFFFFFFF
  return left_rotate(a, s) + b & 0xFFFFFFFF


def II(a, b, c, d, x, s, ac):
  a = (a + bitwise_nor_mix(b, c, d) + x + ac) & 0xFFFFFFFF
  return left_rotate(a, s) + b & 0xFFFFFFFF


def pad_message(message):  # 填充
  original_length_bits = len(message) * 8
  message += b"\x80"
  while (len(message) + 8) % 64 != 0:
    message += b"\x00"
  message += struct.pack("<Q", original_length_bits)
  return message


def md5(inp: bytes | str) -> str:
  """
  :param inp:
  :return:
  """
  # ror   lsl | lsr
  message = inp if isinstance(inp, bytes) else inp.encode()

  a0 = 0x67452301
  b0 = 0xEFCDAB89
  c0 = 0x98BADCFE
  d0 = 0x10325476

  message = pad_message(message)
  chunks = [message[i : i + 64] for i in range(0, len(message), 64)]
  for chunk in chunks:
    words = struct.unpack(
      "<16I", chunk
    )  # 将64字节数据切割16份,每份都按小端续展示. I是int的意思 对应4字节

    A, B, C, D = a0, b0, c0, d0
    # Round 1 都是 a d c b
    A = FF(A, B, C, D, words[0], 7, 0xD76AA478)
    D = FF(D, A, B, C, words[1], 12, 0xE8C7B756)
    C = FF(C, D, A, B, words[2], 17, 0x242070DB)
    B = FF(B, C, D, A, words[3], 22, 0xC1BDCEEE)
    A = FF(A, B, C, D, words[4], 7, 0xF57C0FAF)
    D = FF(D, A, B, C, words[5], 12, 0x4787C62A)
    C = FF(C, D, A, B, words[6], 17, 0xA8304613)
    B = FF(B, C, D, A, words[7], 22, 0xFD469501)
    A = FF(A, B, C, D, words[8], 7, 0x698098D8)
    D = FF(D, A, B, C, words[9], 12, 0x8B44F7AF)
    C = FF(C, D, A, B, words[10], 17, 0xFFFF5BB1)
    B = FF(B, C, D, A, words[11], 22, 0x895CD7BE)
    A = FF(A, B, C, D, words[12], 7, 0x6B901122)
    D = FF(D, A, B, C, words[13], 12, 0xFD987193)
    C = FF(C, D, A, B, words[14], 17, 0xA679438E)
    B = FF(B, C, D, A, words[15], 22, 0x49B40821)
    # Round 2
    A = GG(A, B, C, D, words[1], 5, 0xF61E2562)
    D = GG(D, A, B, C, words[6], 9, 0xC040B340)
    C = GG(C, D, A, B, words[11], 14, 0x265E5A51)
    B = GG(B, C, D, A, words[0], 20, 0xE9B6C7AA)
    A = GG(A, B, C, D, words[5], 5, 0xD62F105D)
    D = GG(D, A, B, C, words[10], 9, 0x02441453)
    C = GG(C, D, A, B, words[15], 14, 0xD8A1E681)
    B = GG(B, C, D, A, words[4], 20, 0xE7D3FBC8)
    A = GG(A, B, C, D, words[9], 5, 0x21E1CDE6)
    D = GG(D, A, B, C, words[14], 9, 0xC33707D6)
    C = GG(C, D, A, B, words[3], 14, 0xF4D50D87)
    B = GG(B, C, D, A, words[8], 20, 0x455A14ED)
    A = GG(A, B, C, D, words[13], 5, 0xA9E3E905)
    D = GG(D, A, B, C, words[2], 9, 0xFCEFA3F8)
    C = GG(C, D, A, B, words[7], 14, 0x676F02D9)
    B = GG(B, C, D, A, words[12], 20, 0x8D2A4C8A)
    # Round 3
    A = HH(A, B, C, D, words[5], 4, 0xFFFA3942)
    D = HH(D, A, B, C, words[8], 11, 0x8771F681)
    C = HH(C, D, A, B, words[11], 16, 0x6D9D6122)
    B = HH(B, C, D, A, words[14], 23, 0xFDE5380C)
    A = HH(A, B, C, D, words[1], 4, 0xA4BEEA44)
    D = HH(D, A, B, C, words[4], 11, 0x4BDECFA9)
    C = HH(C, D, A, B, words[7], 16, 0xF6BB4B60)
    B = HH(B, C, D, A, words[10], 23, 0xBEBFBC70)
    A = HH(A, B, C, D, words[13], 4, 0x289B7EC6)
    D = HH(D, A, B, C, words[0], 11, 0xEAA127FA)
    C = HH(C, D, A, B, words[3], 16, 0xD4EF3085)
    B = HH(B, C, D, A, words[6], 23, 0x04881D05)
    A = HH(A, B, C, D, words[9], 4, 0xD9D4D039)
    D = HH(D, A, B, C, words[12], 11, 0xE6DB99E5)
    C = HH(C, D, A, B, words[15], 16, 0x1FA27CF8)
    B = HH(B, C, D, A, words[2], 23, 0xC4AC5665)
    # Round 4
    A = II(A, B, C, D, words[0], 6, 0xF4292244)
    D = II(D, A, B, C, words[7], 10, 0x432AFF97)
    C = II(C, D, A, B, words[14], 15, 0xAB9423A7)
    B = II(B, C, D, A, words[5], 21, 0xFC93A039)
    A = II(A, B, C, D, words[12], 6, 0x655B59C3)
    D = II(D, A, B, C, words[3], 10, 0x8F0CCC92)
    C = II(C, D, A, B, words[10], 15, 0xFFEFF47D)
    B = II(B, C, D, A, words[1], 21, 0x85845DD1)
    A = II(A, B, C, D, words[8], 6, 0x6FA87E4F)
    D = II(D, A, B, C, words[15], 10, 0xFE2CE6E0)
    C = II(C, D, A, B, words[6], 15, 0xA3014314)
    B = II(B, C, D, A, words[13], 21, 0x4E0811A1)
    A = II(A, B, C, D, words[4], 6, 0xF7537E82)
    D = II(D, A, B, C, words[11], 10, 0xBD3AF235)
    C = II(C, D, A, B, words[2], 15, 0x2AD7D2BB)
    B = II(B, C, D, A, words[9], 21, 0xEB86D391)

    a0 = (a0 + A) & 0xFFFFFFFF
    b0 = (b0 + B) & 0xFFFFFFFF
    c0 = (c0 + C) & 0xFFFFFFFF
    d0 = (d0 + D) & 0xFFFFFFFF

  result = struct.pack("<4I", a0, b0, c0, d0)
  return result.hex()


if __name__ == "__main__":
  print(bytes.fromhex("31"))
  # print(md5(bytes.fromhex('31')))

  # num = 0x12345678
  # print(num.to_bytes(4, byteorder='big').hex())
  # print(num.to_bytes(4, byteorder='little').hex())
