# @time    : 2025/12/24 13:30
# @name    : sha2_512_256.py
# @author  : azwpayne
# @desc    :

"""
SHA-512/256 纯Python实现
遵循FIPS 180-4标准，输出256位摘要
"""

# 初始哈希值 (前32位与SHA-256相同，但为64位表示)
INITIAL_HASH_VALUES = [
  0x22312194FC2BF72C,
  0x9F555FA3C84C64C2,
  0x2393B86B6F53B151,
  0x963877195940EABD,
  0x96283EE2A88EFFE3,
  0xBE5E1E2553863992,
  0x2B0199FC2C85B8AA,
  0x0EB72DDC81C52CA2,
]

# 常量K (前80个质数立方根的小数部分)
K = [
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
]


def rotr(x: int, n: int) -> int:
  """循环右移n位 (64位)"""
  return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def shr(x: int, n: int) -> int:
  """逻辑右移n位"""
  return x >> n


def ch(x: int, y: int, z: int) -> int:
  """选择函数: (x & y) ^ (~x & z)"""
  return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
  """多数函数: (x & y) ^ (x & z) ^ (y & z)"""
  return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x: int) -> int:
  """Σ0函数: ROTR(28) ^ ROTR(34) ^ ROTR(39)"""
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)


def sigma1(x: int) -> int:
  """Σ1函数: ROTR(14) ^ ROTR(18) ^ ROTR(41)"""
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)


def gamma0(x: int) -> int:
  """σ0函数: ROTR(1) ^ ROTR(8) ^ SHR(7)"""
  return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7)


def gamma1(x: int) -> int:
  """σ1函数: ROTR(19) ^ ROTR(61) ^ SHR(6)"""
  return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6)


def pad_message(message: bytes) -> bytes:
  """填充消息：添加1比特和足够的0比特，最后64位存储原始长度"""
  msg_len = len(message)
  bit_len = (msg_len * 8) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  # 添加1比特后填充0到112字节模128
  padding = b"\x80" + b"\x00" * ((112 - (msg_len + 1) % 128) % 128)

  # 附加64位消息长度（大端序）
  return message + padding + bit_len.to_bytes(16, "big")


def process_chunk(chunk: bytes, h: list[int]) -> list[int]:
  """处理128字节的消息块"""
  # 创建消息调度数组
  w = [0] * 80

  # 前16个字来自消息块（64位大端序）
  for i in range(16):
    w[i] = int.from_bytes(chunk[i * 8 : (i + 1) * 8], "big")

  # 扩展消息调度
  for i in range(16, 80):
    w[i] = (
      gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]
    ) & 0xFFFFFFFFFFFFFFFF

  # 初始化工作变量
  a, b, c, d, e, f, g, h_val = h

  # 主循环
  for i in range(80):
    t1 = (h_val + sigma1(e) + ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFFFFFFFFFF
    t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFFFFFFFFFF

    h_val = g
    g = f
    f = e
    e = (d + t1) & 0xFFFFFFFFFFFFFFFF
    d = c
    c = b
    b = a
    a = (t1 + t2) & 0xFFFFFFFFFFFFFFFF

  # 更新哈希值
  return [
    (h[0] + a) & 0xFFFFFFFFFFFFFFFF,
    (h[1] + b) & 0xFFFFFFFFFFFFFFFF,
    (h[2] + c) & 0xFFFFFFFFFFFFFFFF,
    (h[3] + d) & 0xFFFFFFFFFFFFFFFF,
    (h[4] + e) & 0xFFFFFFFFFFFFFFFF,
    (h[5] + f) & 0xFFFFFFFFFFFFFFFF,
    (h[6] + g) & 0xFFFFFFFFFFFFFFFF,
    (h[7] + h_val) & 0xFFFFFFFFFFFFFFFF,
  ]


def sha512_256(message: bytes | str, encoding: str = "utf-8") -> str:
  """
  SHA-512/256哈希函数

  Args:
      message: 输入消息，可以是bytes或str类型
      encoding: 如果message是str，使用此编码转换为bytes

  Returns:
      256位哈希值的十六进制字符串表示
  """
  # 转换为bytes
  if isinstance(message, str):
    message = message.encode(encoding)

  # 初始化哈希值
  h = INITIAL_HASH_VALUES.copy()

  # 填充消息
  padded_message = pad_message(message)

  # 处理每个128字节块
  for i in range(0, len(padded_message), 128):
    chunk = padded_message[i : i + 128]
    h = process_chunk(chunk, h)

  # 截取前256位（4个64位字）
  digest = b"".join(val.to_bytes(8, "big") for val in h[:4])

  return digest.hex()


# 使用示例
if __name__ == "__main__":
  # 测试向量来自NIST
  test_cases = [
    (b"", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"),
    (b"abc", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
    (
      b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
      "835f9207766637f832cb3022f9d386b8b9426876f398d6b013a4925cc752806d",
    ),
  ]

  for msg, expected in test_cases:
    result = sha512_256(msg)
    print(f"消息: {msg[:50]!r}{'...' if len(msg) > 50 else ''}")
    print(f"结果: {result}")
    print(f"正确: {'✓' if result == expected else '✗'}")
