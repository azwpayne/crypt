# @time    : 2025/12/24 13:32
# @name    : sha1.py
# @author  : azwpayne
# @desc    :


def sha1(data):
  def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

  # 初始化哈希值
  h0 = 0x67452301
  h1 = 0xEFCDAB89
  h2 = 0x98BADCFE
  h3 = 0x10325476
  h4 = 0xC3D2E1F0

  # 预处理
  original_byte_len = len(data)
  original_bit_len = original_byte_len * 8
  data += b"\x80"

  while (len(data) + 8) % 64 != 0:
    data += b"\x00"

  data += original_bit_len.to_bytes(8, "big")  # 附加消息长度 大端序

  # 处理每个512-bit块
  for i in range(0, len(data), 64):
    w = [0] * 80
    chunk = data[i : i + 64]
    # 将块划分为16个32-bit字
    for j in range(16):
      w[j] = int.from_bytes(chunk[4 * j : 4 * j + 4], "big")

    # 扩展到80个字
    for j in range(16, 80):
      w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

    a, b, c, d, e = h0, h1, h2, h3, h4

    # 主循环
    for j in range(80):
      if 0 <= j <= 19:
        f = (b & c) | (~b & d)
        k = 0x5A827999
      elif 20 <= j <= 39:
        f = b ^ c ^ d
        k = 0x6ED9EBA1
      elif 40 <= j <= 59:
        f = (b & c) | (b & d) | (c & d)
        k = 0x8F1BBCDC
      elif 60 <= j <= 79:
        f = b ^ c ^ d
        k = 0xCA62C1D6
      temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
      e = d
      d = c
      c = left_rotate(b, 30)
      b = a
      a = temp

    h0 = (h0 + a) & 0xFFFFFFFF
    h1 = (h1 + b) & 0xFFFFFFFF
    h2 = (h2 + c) & 0xFFFFFFFF
    h3 = (h3 + d) & 0xFFFFFFFF
    h4 = (h4 + e) & 0xFFFFFFFF

  return "".join(f"{x:08x}" for x in [h0, h1, h2, h3, h4])


# message = "yangruhua"
#
# data = message.encode()
# data = b'yangruhua'
#
# data = bytes.fromhex('79616e677275687561')
#
# hash_value = sha1(data)
# print(hash_value)
