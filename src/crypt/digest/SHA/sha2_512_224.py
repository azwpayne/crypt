# @time    : 2025/12/24 13:30
# @name    : sha2_512_224.py
# @author  : azwpayne
# @desc    :

import hashlib
from secrets import randbelow
from string import printable

# 初始哈希值 (FIPS 180-4 第 5.3.4.2 节)
INITIAL_HASH = (
  0x8C3D37C819544DA2,
  0x73E1996689DCD4D6,
  0x1DFAB7AE32FF9C82,
  0x679DD514582F9FCF,
  0x0F6D2B697BD44DA8,
  0x77E36F7304C48942,
  0x3F9D85A86A1D36C8,
  0x1112E6AD91D692A1,
)

# 轮常数 (FIPS 180-4 第 4.2.3 节)
ROUND_CONSTANTS = (
  0x428A2F98D728AE22,
  0x7137449123EF65CD,
  0xB5C0FBCFEC4D3B2F,
  0xE9B5DBA58189DBBC,
  0x3956C25BF348B538,
  0x59F111F1B605D019,
  0x923F82A4AF194F9B,
  0xAB1C5ED5DA6D8118,
  0xD807AA98A3030242,
  0x12835B0145706FBE,
  0x243185BE4EE4B28C,
  0x550C7DC3D5FFB4E2,
  0x72BE5D74F27B896F,
  0x80DEB1FE3B1696B1,
  0x9BDC06A725C71235,
  0xC19BF174CF692694,
  0xE49B69C19EF14AD2,
  0xEFBE4786384F25E3,
  0x0FC19DC68B8CD5B5,
  0x240CA1CC77AC9C65,
  0x2DE92C6F592B0275,
  0x4A7484AA6EA6E483,
  0x5CB0A9DCBD41FBD4,
  0x76F988DA831153B5,
  0x983E5152EE66DFAB,
  0xA831C66D2DB43210,
  0xB00327C898FB213F,
  0xBF597FC7BEEF0EE4,
  0xC6E00BF33DA88FC2,
  0xD5A79147930AA725,
  0x06CA6351E003826F,
  0x142929670A0E6E70,
  0x27B70A8546D22FFC,
  0x2E1B21385C26C926,
  0x4D2C6DFC5AC42AED,
  0x53380D139D95B3DF,
  0x650A73548BAF63DE,
  0x766A0ABB3C77B2A8,
  0x81C2C92E47EDAEE6,
  0x92722C851482353B,
  0xA2BFE8A14CF10364,
  0xA81A664BBC423001,
  0xC24B8B70D0F89791,
  0xC76C51A30654BE30,
  0xD192E819D6EF5218,
  0xD69906245565A910,
  0xF40E35855771202A,
  0x106AA07032BBD1B8,
  0x19A4C116B8D2D0C8,
  0x1E376C085141AB53,
  0x2748774CDF8EEB99,
  0x34B0BCB5E19B48A8,
  0x391C0CB3C5C95A63,
  0x4ED8AA4AE3418ACB,
  0x5B9CCA4F7763E373,
  0x682E6FF3D6B2B8A3,
  0x748F82EE5DEFB2FC,
  0x78A5636F43172F60,
  0x84C87814A1F0AB72,
  0x8CC702081A6439EC,
  0x90BEFFFA23631E28,
  0xA4506CEBDE82BDE9,
  0xBEF9A3F7B2C67915,
  0xC67178F2E372532B,
  0xCA273ECEEA26619C,
  0xD186B8C721C0C207,
  0xEADA7DD6CDE0EB1E,
  0xF57D4F7FEE6ED178,
  0x06F067AA72176FBA,
  0x0A637DC5A2C898A6,
  0x113F9804BEF90DAE,
  0x1B710B35131C471B,
  0x28DB77F523047D84,
  0x32CAAB7B40C72493,
  0x3C9EBE0A15C9BEBC,
  0x431D67C49C100D4C,
  0x4CC5D4BECB3E42B6,
  0x597F299CFC657E2A,
  0x5FCB6FAB3AD6FAEC,
  0x6C44198C4A475817,
)


def right_rotate(n: int, bits: int) -> int:
  """64位右循环移位"""
  return ((n >> bits) | (n << (64 - bits))) & 0xFFFFFFFFFFFFFFFF


def right_shift(n: int, bits: int) -> int:
  """64位右移"""
  return n >> bits


def ch(x: int, y: int, z: int) -> int:
  """选择函数: (x & y) ^ (~x & z)"""
  return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
  """多数函数: (x & y) ^ (x & z) ^ (y & z)"""
  return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x: int) -> int:
  """Σ0 函数: ROTR(28) ^ ROTR(34) ^ ROTR(39)"""
  return right_rotate(x, 28) ^ right_rotate(x, 34) ^ right_rotate(x, 39)


def sigma1(x: int) -> int:
  """Σ1 函数: ROTR(14) ^ ROTR(18) ^ ROTR(41)"""
  return right_rotate(x, 14) ^ right_rotate(x, 18) ^ right_rotate(x, 41)


def gamma0(x: int) -> int:
  """σ0 函数: ROTR(1) ^ ROTR(8) ^ SHR(7)"""
  return right_rotate(x, 1) ^ right_rotate(x, 8) ^ right_shift(x, 7)


def gamma1(x: int) -> int:
  """σ1 函数: ROTR(19) ^ ROTR(61) ^ SHR(6)"""
  return right_rotate(x, 19) ^ right_rotate(x, 61) ^ right_shift(x, 6)


def pad_message(message: bytes) -> bytes:
  """
  消息填充 (FIPS 180-4 第 5.1.1 节)
  格式: [原始消息] + 1 + [0...0] + [128位长度]
  """
  msg_len = len(message)
  bit_len = (msg_len * 8) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  # 添加1位
  padded = message + b"\x80"

  # 填充0直到长度 ≡ 112 mod 128
  while len(padded) % 128 != 112:
    padded += b"\x00"

  # 附加128位长度 (大端序)
  padded += bit_len.to_bytes(16, "big")

  return padded


def chunk_message(padded: bytes) -> tuple[tuple[int, ...], ...]:
  """
  将填充后的消息分割为 128 字节的块
  每个块转换为 16 个 64 位字 (大端序)
  """
  return tuple(
    tuple(int.from_bytes(padded[i + j : i + j + 8], "big") for j in range(0, 128, 8))
    for i in range(0, len(padded), 128)
  )


# ============================================================================
# 消息调度
# ============================================================================


def message_schedule(block: tuple[int, ...]) -> tuple[int, ...]:
  """
  消息扩展 (FIPS 180-4 第 6.4.2 节)
  将16个消息字扩展为80个
  """
  w = list(block)

  for i in range(16, 80):
    s0 = gamma0(w[i - 15])
    s1 = gamma1(w[i - 2])
    w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF)

  return tuple(w)


# ============================================================================
# 压缩函数
# ============================================================================

# def compress_block(
#         h: Tuple[int, ...],
#         w: Tuple[int, ...],
#         k: Tuple[int, ...],
# ) -> Tuple[int, ...]:
#     """
#     块压缩函数 (FIPS 180-4 第 6.4.2 节)
#     """
#     a, b, c, d, e, f, g, h_val = h
#
#     for i in range(80):
#         # 计算 T1
#         ch_val = ch(e, f, g)
#         sigma1_val = sigma1(e)
#         t1 = (h_val + sigma1_val + ch_val + k[i] + w[i]) & 0xFFFFFFFFFFFFFFFF
#
#         # 计算 T2
#         sigma0_val = sigma0(a)
#         maj_val = maj(a, b, c)
#         t2 = (sigma0_val + maj_val) & 0xFFFFFFFFFFFFFFFF
#
#         # 更新工作变量
#         h_val = g
#         g = f
#         f = e
#         e = (d + t1) & 0xFFFFFFFFFFFFFFFF
#         d = c
#         c = b
#         b = a
#         a = (t1 + t2) & 0xFFFFFFFFFFFFFFFF
#
#     return (a, b, c, d, e, f, g, h_val)


def compress_block(
  h: tuple[int, ...],
  w: tuple[int, ...],
  k: tuple[int, ...],
) -> tuple[int, ...]:
  """
  块压缩函数 (FIPS 180-4 第 6.4.2 节)
  """
  a, b, c, d, e, f, g, h_val = h

  for i in range(80):
    # 计算 T1
    ch_val = ch(e, f, g)
    sigma1_val = sigma1(e)
    t1 = (h_val + sigma1_val + ch_val + k[i] + w[i]) & 0xFFFFFFFFFFFFFFFF

    # 计算 T2
    sigma0_val = sigma0(a)
    maj_val = maj(a, b, c)
    t2 = (sigma0_val + maj_val) & 0xFFFFFFFFFFFFFFFF

    # 同时更新工作变量，避免变量覆盖问题
    h_val, g, f, e, d, c, b, a = (
      g,
      f,
      e,
      (d + t1) & 0xFFFFFFFFFFFFFFFF,
      c,
      b,
      a,
      (t1 + t2) & 0xFFFFFFFFFFFFFFFF,
    )

  return a, b, c, d, e, f, g, h_val


# ============================================================================
# 主哈希函数
# ============================================================================

# def sha512_224(message: bytes) -> bytes:
#     """
#     SHA-512/224 哈希函数 (FIPS 180-4)
#
#     参数:
#         message: 输入消息字节串
#
#     返回:
#         224 位 (28 字节) 哈希值
#     """
#     # 初始化哈希值
#     h = INITIAL_HASH
#
#     # 消息预处理
#     padded = pad_message(message)
#     blocks = chunk_message(padded)
#
#     # 处理每个块
#     for block in blocks:
#         w = message_schedule(block)
#         h = compress_block(h, w, ROUND_CONSTANTS)
#
#         # 与前一哈希值相加
#         h = tuple(
#             (x + y) & 0xFFFFFFFFFFFFFFFF
#             for x, y in zip(INITIAL_HASH, h)
#         )
#
#     # 提取前224位 (7个64位字)
#     digest = b''.join(
#         word.to_bytes(8, 'big')
#         for word in h[:7]  # 7 * 64 = 448 位，但需要截断到224位
#     )
#
#     # 截断到224位 (28字节)
#     return digest[:28]


def sha512_224(message: bytes) -> bytes:
  """
  SHA-512/224 哈希函数 (FIPS 180-4)

  参数:
      message: 输入消息字节串

  返回:
      224 位 (28 字节) 哈希值
  """
  # 初始化哈希值
  h = INITIAL_HASH

  # 消息预处理
  padded = pad_message(message)
  blocks = chunk_message(padded)

  # 处理每个块
  for block in blocks:
    w = message_schedule(block)
    # 注意：这里是关键 - 压缩函数应该使用当前哈希值作为输入
    h_new = compress_block(h, w, ROUND_CONSTANTS)

    # 将压缩结果与当前哈希值相加（这是正确的）
    h = tuple(
      (current + new) & 0xFFFFFFFFFFFFFFFF
      for current, new in zip(h, h_new, strict=False)
    )

  # 提取前224位 (28字节)
  full_digest = b"".join(word.to_bytes(8, "big") for word in h)

  # 截断到224位 (28字节)
  return full_digest[:28]


# ============================================================================
# 辅助函数
# ============================================================================


def sha512_224_hex(message: bytes) -> str:
  """返回十六进制格式的哈希值"""
  return sha512_224(message).hex()


# ============================================================================
# 测试
# ============================================================================

if __name__ == "__main__":
  for _ in range(0x10):
    example_str = "".join(
      printable[randbelow(len(printable))] for _ in range(randbelow(0x10) + 1)
    )
    print(f"输入字符串: {example_str}")
    result = sha512_224_hex(example_str.encode())

    status = (
      "✓"
      if result == hashlib.new("sha512_224", example_str.encode()).hexdigest()
      else "✗"
    )
    print(f"输出结果: {result}")
    print(f"验证结果: {status}")

  # 测试向量来自 FIPS 180-4
  test_cases = [
    (b"", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"),
    (b"abc", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
    (b"abcd", "0c9f157ab030fb06e957c14e3938dc5908962e5dd7b66f04a36fc534"),
    (b"abcde", "880e79bb0a1d2c9b7528d851edb6b8342c58c831de98123b432a4515"),
    (b"abcdef", "236c829cfea4fd6d4de61ad15fcf34dca62342adaf9f2001c16f29b8"),
    (b"abcdefg", "4767af672b3ed107f25018dc22d6fa4b07d156e13b720971e2c4f6bf"),
    (b"abcdefgh", "792e25e0ae286d123a38950007e037d3122e76c4ee201668c385edab"),
    (
      b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
      "fc9be3101845460350061160d05d1092d5d2eb72d62efcaa4f453bf7",
    ),
  ]

  print("测试 SHA-512/224 实现...")
  for i, (message, expected) in enumerate(test_cases, 1):
    result = sha512_224_hex(message)
    status = "✓" if result == expected else "✗"
    print(f"测试 {i}: {status}")
    print(f"  消息: {message[:50]}")
    print(f"  期望: {expected}")
    print(f"  结果: {result}")
    print()

  # 自定义测试
  print("自定义测试:")
  custom_message = b"hello world"
  print(f"sha512_224(b'{custom_message.decode()}') = {sha512_224_hex(custom_message)}")
