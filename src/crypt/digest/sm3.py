# @time    : 2025/12/24 13:29
# @name    : sm3.py
# @author  : azwpayne
# @desc    :


def left_rotate(value, shift_bits):
  """
  对32位整数进行左循环移位

  :param value: 要移位的32位整数
  :param shift_bits: 左移的位数
  :return: 循环移位后的32位整数
  """
  # 规范化移位位数到0-31范围内
  normalized_shift = shift_bits % 32
  # 如果移位位数为0，直接返回原值
  if normalized_shift == 0:
    return value & 0xFFFFFFFF
  # 执行左循环移位操作
  # 将value左移normalized_shift位，同时将右边被移出的位移到左边
  return ((value << normalized_shift) | (value >> (32 - normalized_shift))) & 0xFFFFFFFF


# 常量 Tj，定义为两个不同的值
T = [0x79CC4519 if j < 16 else 0x7A879D8A for j in range(64)]


# 压缩函数 FFj 和 GGj 的定义
def ff(x, y, z, j):
  return x ^ y ^ z if j < 16 else (x & y) | (x & z) | (y & z)


def gg(x, y, z, j):
  """
  计算SM3哈希算法中的布尔函数GG。该函数在前16轮和后48轮采用不同的逻辑运算形式，以增强消息的非线性混淆特性。

  :param x: 32位整数输入X
  :param y: 32位整数输入Y
  :param z: 32位整数输入Z
  :param j: 轮次索引（0-63），用于选择不同的布尔函数形式
  :return: 计算得到的32位整数结果
  """
  return x ^ y ^ z if j < 16 else (x & y) | (~x & z)


# P0 和 P1 置换函数
def p0(x):
  return x ^ left_rotate(x, 9) ^ left_rotate(x, 17)


def p1(x):
  return x ^ left_rotate(x, 15) ^ left_rotate(x, 23)


# 填充消息，使得消息长度是 512 位的倍数
def padding(message):
  msg_len = len(message) * 8
  message += b"\x80"
  while (len(message) + 8) % 64 != 0:
    message += b"\x00"
  message += msg_len.to_bytes(8, "big")
  return message


# 消息扩展函数
def message_expand(block):
  w = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
  w.extend(
    p1(w[j - 16] ^ w[j - 9] ^ left_rotate(w[j - 3], 15))
    ^ left_rotate(w[j - 13], 7)
    ^ w[j - 6]
    for j in range(16, 68)
  )
  w_ = [w[j] ^ w[j + 4] for j in range(64)]
  return w, w_


# 压缩函数 CF
def cf(v, block):
  a, b, c, d, e, f, g, h = v
  w, w_ = message_expand(block)

  for j in range(64):
    ss1 = left_rotate(
      (left_rotate(a, 12) + e + left_rotate(T[j], j % 32)) & 0xFFFFFFFF, 7
    )
    ss2 = ss1 ^ left_rotate(a, 12)

    tt1 = (ff(a, b, c, j) + d + ss2 + w_[j]) & 0xFFFFFFFF
    tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF

    d = c
    c = left_rotate(b, 9)
    b = a
    a = tt1
    h = g
    g = left_rotate(f, 19)
    f = e
    e = p0(tt2)

  return [(v[i] ^ x) & 0xFFFFFFFF for i, x in enumerate([a, b, c, d, e, f, g, h])]


# 主函数
def sm3(message):
  """
  计算给定消息的SM3哈希值。该函数实现了SM3摘要算法的完整流程，包括填充、分组和压缩等步骤。

  该函数返回摘要结果的16进制字符串表示形式，可用于完整性校验和签名等密码学应用场景。

  Args:
      message: 原始输入消息的字节序列

  Returns: 32字节长度的SM3哈希值对应的64位16进制字符串

  """
  # 初始向量 IV
  iv = [
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
  ]

  m = padding(message)
  blocks = [m[i : i + 64] for i in range(0, len(m), 64)]

  v = iv
  for block in blocks:
    v = cf(v, block)

  return "".join(f"{x:08x}" for x in v)
