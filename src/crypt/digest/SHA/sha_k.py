# @author  : azwpayne(https://github.com/azwpayne)
# @name    : sha_k.py
# @time    : 2026/3/11 00:57 Wed
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :

from utils import generate_n_sieve


def generate_sha2_k_table():
  """
  生成 SHA-256 的 K 表（64 个 32 位常量）
  原理：前 64 个质数(小数部分)的立方根 * 2^32 取整
  Returns:
    list[int]: 包含 64 个 32 位无符号整数的 K 表
  Examples:
    >>> k_table = generate_sha2_k_table()
    >>> len(k_table)
    64
    >>> all(0 <= k <= 0xFFFFFFFF for k in k_table)
    True
  """

  # # 1. 生成前 64 个质数
  sieve = generate_n_sieve(64)

  # 2. 计算 K
  # k_table = []
  # for p in sieve:
  #   # 计算立方根（浮点数精度对于 32 位结果足够）
  #   cube_root = p ** (1.0 / 3.0)
  #   # 取小数部分
  #   fractional = cube_root - int(cube_root)
  #   # 乘以 2^32 并取整，确保为 32 位无符号整数
  #   k_value = int(fractional * (2**32)) & 0xFFFFFFFF
  #   k_table.append(k_value)
  #
  # return k_table
  return [
    int((p ** (1.0 / 3.0) - int(p ** (1.0 / 3.0))) * (2**32)) & 0xFFFFFFFF
    for p in sieve
  ]


# 3. 验证与标准 SHA-256 常量是否一致
def verify_k_table():
  """与 FIPS 180-4 标准值对比验证"""
  expected = [
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
  ]

  generated = generate_sha2_k_table()

  if generated == expected:
    print("✓ 验证通过: 生成的 K 表与 FIPS 180-4 标准完全一致")
    return True
  print("✗ 验证失败")
  for i, (g, e) in enumerate(zip(generated, expected, strict=False)):
    if g != e:
      print(f"  K[{i}] 不匹配: 生成 0x{g:08x}, 期望 0x{e:08x}")
  return False


# 4. 格式化输出
def print_k_table():
  """按标准格式打印 K 表"""
  k_table = generate_sha2_k_table()
  print("SHA-256 K 表(64 个常量):")
  print("-" * 70)
  for i in range(0, 64, 8):
    row = ", ".join(f"0x{k_table[j]:08x}" for j in range(i, min(i + 8, 64)))
    print(f"    {row}," if i < 56 else f"    {row}")


if __name__ == "__main__":
  print_k_table()
  print()
  verify_k_table()

  # 额外展示前 3 个的计算细节
  print("\n前 3 个常量的计算细节：")
  primes = [2, 3, 5]
  for pr in primes:
    cr = pr ** (1.0 / 3.0)
    frac = cr - int(cr)
    kk = int(frac * (2**32))
    print(f"  质数 {pr:2d}: ³√{pr} ≈ {cr:.10f}, 小数部分 × 2³² = {kk:10d} (0x{kk:08x})")
