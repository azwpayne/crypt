# @time    : 2026/1/6 16:36
# @name    : sha2_384.py
# @author  : azwpayne
# @desc    :

"""
SHA-384 哈希算法的纯 Python 实现
遵循 FIPS 180-4 标准，采用函数式编程风格
"""

# 初始哈希值（来自 SHA-384 标准）
INITIAL_HASH_VALUES = [
  0xCBBB9D5DC1059ED8,
  0x629A292A367CD507,
  0x9159015A3070DD17,
  0x152FECD8F70E5939,
  0x67332667FFC00B31,
  0x8EB44A8768581511,
  0xDB0C2E0D64F98FA7,
  0x47B5481DBEFA4FA4,
]

# 前 64 个素数的立方根小数部分常数
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


def _right_rotate(n: int, bits: int) -> int:
  """64位右循环移位"""
  return ((n >> bits) | (n << (64 - bits))) & 0xFFFFFFFFFFFFFFFF


def _maj(x: int, y: int, z: int) -> int:
  """majority 函数: (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)"""
  return (x & y) ^ (x & z) ^ (y & z)


def _ch(x: int, y: int, z: int) -> int:
  """选择函数: (x ∧ y) ⊕ (¬x ∧ z)"""
  return (x & y) ^ ((~x) & z)


def _sigma0(x: int) -> int:
  """Σ0 函数: ROTR(28, x) ⊕ ROTR(34, x) ⊕ ROTR(39, x)"""
  return _right_rotate(x, 28) ^ _right_rotate(x, 34) ^ _right_rotate(x, 39)


def _sigma1(x: int) -> int:
  """Σ1 函数: ROTR(14, x) ⊕ ROTR(18, x) ⊕ ROTR(41, x)"""
  return _right_rotate(x, 14) ^ _right_rotate(x, 18) ^ _right_rotate(x, 41)


def _gamma0(x: int) -> int:
  """σ0 函数: ROTR(1, x) ⊕ ROTR(8, x) ⊕ SHR(7, x)"""
  return _right_rotate(x, 1) ^ _right_rotate(x, 8) ^ (x >> 7)


def _gamma1(x: int) -> int:
  """σ1 函数: ROTR(19, x) ⊕ ROTR(61, x) ⊕ SHR(6, x)"""
  return _right_rotate(x, 19) ^ _right_rotate(x, 61) ^ (x >> 6)


def _pad_message(message: bytes) -> bytes:
  """
  消息填充：追加 1 和 0，最后附加 128 位消息长度
  填充后长度为 1024 位的倍数
  """
  msg_len = len(message) * 8  # 原始消息长度（位）
  message += b"\x80"  # 追加 1 位

  # 填充 0 直到长度 ≡ 112 mod 128
  while (len(message) % 128) != 112:  # noqa: PLR2004
    message += b"\x00"

  # 追加 128 位消息长度（大端序）
  message += msg_len.to_bytes(16, "big")
  return message


def _process_block(block: bytes, h: list) -> list:
  """
  处理单个 1024 位消息块
  block: 128 字节消息块
  h: 8 个 64 位哈希值组成的列表
  """
  # 消息调度：将 1024 位块扩展为 80 个 64 位字
  w = [int.from_bytes(block[i : i + 8], "big") for i in range(0, 128, 8)]
  w += [0] * (80 - 16)

  for t in range(16, 80):
    w[t] = (
      _gamma1(w[t - 2]) + w[t - 7] + _gamma0(w[t - 15]) + w[t - 16]
    ) & 0xFFFFFFFFFFFFFFFF

  # 初始化工作变量
  a, b, c, d, e, f, g, h0 = h

  # 80 轮主循环
  for t in range(80):
    t1 = (h0 + _sigma1(e) + _ch(e, f, g) + K[t] + w[t]) & 0xFFFFFFFFFFFFFFFF
    t2 = (_sigma0(a) + _maj(a, b, c)) & 0xFFFFFFFFFFFFFFFF

    h0 = g
    g = f
    f = e
    e = (d + t1) & 0xFFFFFFFFFFFFFFFF
    d = c
    c = b
    b = a
    a = (t1 + t2) & 0xFFFFFFFFFFFFFFFF

  # 更新哈希值
  return [
    (x + y) & 0xFFFFFFFFFFFFFFFF
    for x, y in zip([a, b, c, d, e, f, g, h0], h, strict=False)
  ]


def sha384(message: bytes) -> bytes:
  """
  SHA-384 哈希函数主入口

  Args:
      message: 输入字节串

  Returns:
      48 字节（384 位）哈希值
  """
  # 初始化哈希值
  hash_values = INITIAL_HASH_VALUES.copy()

  # 消息填充
  padded_message = _pad_message(message)

  # 逐块处理
  for i in range(0, len(padded_message), 128):
    block = padded_message[i : i + 128]
    hash_values = _process_block(block, hash_values)

  # 输出：将 8 个 64 位字连接并截断为 384 位（前 6 个字）
  return b"".join(h.to_bytes(8, "big") for h in hash_values[:6])


def sha384_hex(message: bytes) -> str:
  """
  返回十六进制格式的 SHA-384 哈希值
  """
  return sha384(message).hex()


# 测试向量
def _run_tests():
  """NIST 测试向量验证"""
  test_cases = [
    (
      b"",
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    ),
    (
      b"abc",
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    ),
    (
      b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
    ),
  ]

  for i, (msg, expected) in enumerate(test_cases, 1):
    result = sha384_hex(msg)
    status = "✓" if result == expected else "✗"
    print(f"Test {i}: {status}")
    print(f"  Expected: {expected}")
    print(f"  Got:      {result}")
    print()

  # 额外测试：验证消息长度边界
  large_msg = b"a" * 1000000
  expected_large = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
  result_large = sha384_hex(large_msg)
  print(
    f"Large message test (1M 'a'): {'✓' if result_large == expected_large else '✗'}"
  )


if __name__ == "__main__":
  _run_tests()
