# @time    : 2025/12/24 13:31
# @name    : sha2_256.py
# @author  : azwpayne
# @desc    :


import struct


def right_rotate(value, shift_bits):
  """
  对32位整数进行右循环移位

  :param value: 要移位的32位整数
  :param shift_bits: 右移的位数
  :return: 循环移位后的32位整数
  """
  # 规范化移位位数到0-31范围内
  normalized_shift = shift_bits % 32
  # 如果移位位数为0，直接返回原值
  if normalized_shift == 0:
    return value & 0xFFFFFFFF
  # 执行右循环移位操作
  return ((value >> normalized_shift) | (value << (32 - normalized_shift))) & 0xFFFFFFFF


# 常量
K = (
  0x428A2F98,
  0x71374491,
  0xB5C0FBCF,
  0xE9B5DBA5,
  0x3956C25B,
  0x59F111F1,
  0x923F82A4,
  0xAB1C5ED5,
  0xD807AA98,
  0x12835B01,
  0x243185BE,
  0x550C7DC3,
  0x72BE5D74,
  0x80DEB1FE,
  0x9BDC06A7,
  0xC19BF174,
  0xE49B69C1,
  0xEFBE4786,
  0x0FC19DC6,
  0x240CA1CC,
  0x2DE92C6F,
  0x4A7484AA,
  0x5CB0A9DC,
  0x76F988DA,
  0x983E5152,
  0xA831C66D,
  0xB00327C8,
  0xBF597FC7,
  0xC6E00BF3,
  0xD5A79147,
  0x06CA6351,
  0x14292967,
  0x27B70A85,
  0x2E1B2138,
  0x4D2C6DFC,
  0x53380D13,
  0x650A7354,
  0x766A0ABB,
  0x81C2C92E,
  0x92722C85,
  0xA2BFE8A1,
  0xA81A664B,
  0xC24B8B70,
  0xC76C51A3,
  0xD192E819,
  0xD6990624,
  0xF40E3585,
  0x106AA070,
  0x19A4C116,
  0x1E376C08,
  0x2748774C,
  0x34B0BCB5,
  0x391C0CB3,
  0x4ED8AA4A,
  0x5B9CCA4F,
  0x682E6FF3,
  0x748F82EE,
  0x78A5636F,
  0x84C87814,
  0x8CC70208,
  0x90BEFFFA,
  0xA4506CEB,
  0xBEF9A3F7,
  0xC67178F2,
)
# 初始哈希值
H = (
  0x6A09E667,
  0xBB67AE85,
  0x3C6EF372,
  0xA54FF53A,
  0x510E527F,
  0x9B05688C,
  0x1F83D9AB,
  0x5BE0CD19,
)


def sha256(data: bytes):
  # 步骤 1: 填充消息
  original_byte_len = len(data)
  original_bit_len = original_byte_len * 8
  data += b"\x80"
  data += b"\x00" * ((56 - (original_byte_len + 1) % 64) % 64)
  data += struct.pack(">Q", original_bit_len)

  # 步骤 2: 解析消息为512-bit块
  blocks = [data[i : i + 64] for i in range(0, len(data), 64)]

  # 步骤 3: 初始化工作变量
  hash_pieces = H[:]

  # 步骤 4: 处理每一个块
  for block in blocks:
    W = list(struct.unpack(">16L", block)) + [0] * 48

    for i in range(16, 64):
      s0 = right_rotate(W[i - 15], 7) ^ right_rotate(W[i - 15], 18) ^ (W[i - 15] >> 3)
      s1 = right_rotate(W[i - 2], 17) ^ right_rotate(W[i - 2], 19) ^ (W[i - 2] >> 10)
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = hash_pieces

    for i in range(64):
      S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)  # e
      ch = (e & f) ^ (~e & g)  # e f g
      temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF  # h

      S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)  # a
      maj = (a & b) ^ (a & c) ^ (b & c)  # a b c
      temp2 = (S0 + maj) & 0xFFFFFFFF

      h = g
      g = f
      f = e
      e = (d + temp1) & 0xFFFFFFFF
      d = c
      c = b
      b = a
      a = (temp1 + temp2) & 0xFFFFFFFF

    hash_pieces = [
      (x + y) & 0xFFFFFFFF
      for x, y in zip(hash_pieces, [a, b, c, d, e, f, g, h], strict=False)
    ]
  # 步骤 5: 拼接哈希值
  return "".join(f"{piece:08x}" for piece in hash_pieces)


# hash_value = sha256('yangruhua'.encode())
# print(f'SHA-256: {hash_value}')
if __name__ == "__main__":
  print(sha256(b""))
  print(sha256(b"abc"))
