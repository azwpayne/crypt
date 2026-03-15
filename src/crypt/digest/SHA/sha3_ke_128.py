# @time    : 2026/1/6 16:51
# @name    : sha3_ke_128.py.py
# @author  : azwpayne
# @desc    :

# !/usr/bin/env python3
"""
SHA3-256 纯函数实现
符合 FIPS 202 标准
使用函数式编程风格，不使用类
"""

# ========== 常量和参数 ==========
# SHA3-256 参数
RATE = 1088  # 比特率 (bits)
CAPACITY = 512  # 容量 (bits)
LANE_SIZE = 64  # 每个 lane 的比特数
STATE_SIZE = 5  # 5x5 的 state
ROUNDS = 24  # Keccak-f 轮数
OUTPUT_BITS = 256  # 输出长度 (bits)
BLOCK_SIZE = RATE // 8  # 字节块大小

# 轮常数 RC[i]
RC = [
  0x0000000000000001,
  0x0000000000008082,
  0x800000000000808A,
  0x8000000080008000,
  0x000000000000808B,
  0x0000000080000001,
  0x8000000080008081,
  0x8000000000008009,
  0x000000000000008A,
  0x0000000000000088,
  0x0000000080008009,
  0x000000008000000A,
  0x000000008000808B,
  0x800000000000008B,
  0x8000000000008089,
  0x8000000000008003,
  0x8000000000008002,
  0x8000000000000080,
  0x000000000000800A,
  0x800000008000000A,
  0x8000000080008081,
  0x8000000000008080,
  0x0000000080000001,
  0x8000000080008008,
]

# 旋转偏移表
RHO_OFFSETS = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]

# π 置换表
PI_INDICES = [[0, 3, 1, 4, 2], [0, 0, 0, 0, 0]]  # 第二行不会被用到


# ========== 辅助函数 ==========
def rot64(x, n):
  """64 位循环左移"""
  n = n % 64
  return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def bytes_to_lanes(data):
  """
  将字节数组转换为 5x5 的 lane 矩阵
  每个 lane 是 64 位整数
  """
  if len(data) < 200:  # 200 bytes = 1600 bits
    data = data.ljust(200, b"\x00")

  lanes = [[0] * 5 for _ in range(5)]
  for y in range(5):
    for x in range(5):
      index = 8 * (5 * y + x)
      lane_value = 0
      for i in range(8):
        lane_value |= data[index + i] << (8 * i)
      lanes[x][y] = lane_value
  return lanes


def lanes_to_bytes(lanes):
  """将 lane 矩阵转换为字节数组"""
  data = bytearray(200)
  for y in range(5):
    for x in range(5):
      lane = lanes[x][y]
      index = 8 * (5 * y + x)
      for i in range(8):
        data[index + i] = (lane >> (8 * i)) & 0xFF
  return bytes(data)


# ========== Keccak-f 轮函数 ==========
def theta(state):
  """θ 步骤"""
  C = [0] * 5
  D = [0] * 5

  # 计算 C
  for x in range(5):
    C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]

  # 计算 D
  for x in range(5):
    D[x] = C[(x - 1) % 5] ^ rot64(C[(x + 1) % 5], 1)

  # 更新 state
  new_state = [[0] * 5 for _ in range(5)]
  for x in range(5):
    for y in range(5):
      new_state[x][y] = state[x][y] ^ D[x]

  return new_state


def rho(state):
  """ρ 步骤"""
  new_state = [[0] * 5 for _ in range(5)]
  new_state[0][0] = state[0][0]

  x, y = 1, 0
  for _t in range(24):
    new_state[x][y] = rot64(state[x][y], RHO_OFFSETS[x][y])
    x, y = y, (2 * x + 3 * y) % 5

  return new_state


def pi(state):
  """π 步骤"""
  new_state = [[0] * 5 for _ in range(5)]
  for x in range(5):
    for y in range(5):
      new_state[y][(2 * x + 3 * y) % 5] = state[x][y]
  return new_state


def chi(state):
  """χ 步骤"""
  new_state = [[0] * 5 for _ in range(5)]
  for x in range(5):
    for y in range(5):
      new_state[x][y] = state[x][y] ^ ((~state[(x + 1) % 5][y]) & state[(x + 2) % 5][y])
  return new_state


def iota(state, round_idx):
  """ι 步骤"""
  new_state = [row[:] for row in state]  # 深拷贝
  new_state[0][0] ^= RC[round_idx]
  return new_state


def keccak_f(state):
  """完整的 Keccak-f[1600] 置换"""
  current_state = state

  for round_idx in range(ROUNDS):
    current_state = theta(current_state)
    current_state = rho(current_state)
    current_state = pi(current_state)
    current_state = chi(current_state)
    current_state = iota(current_state, round_idx)

  return current_state


# ========== 海绵结构 ==========
def pad_message(message):
  """
  SHA3-256 填充 (pad10 * 1)
  返回填充后的字节数组
  """
  # 计算需要填充的位数
  # 填充规则: 1 + 0* + 1
  # 总长度 ≡ 0 (mod RATE)

  rate_bytes = RATE // 8
  message_len = len(message)

  # 计算填充后的长度
  # 需要添加: 0x06 + 0x80
  # 实际上: 添加 0x06, 然后补 0x00, 最后添加 0x80

  # 计算当前块剩余空间
  remaining = message_len % rate_bytes
  padding_len = rate_bytes - remaining

  if padding_len == 1:
    # 特殊情况: 需要额外一个块
    padding = bytes([0x86])  # 0x06 | 0x80
  else:
    padding = bytearray([0x06])
    padding.extend([0] * (padding_len - 2))
    padding.append(0x80)
    padding = bytes(padding)

  return message + padding


def absorb(initial_state, message):
  """
  吸收阶段
  initial_state: 初始状态 (全0)
  message: 已填充的消息
  """
  state = initial_state
  rate_bytes = RATE // 8

  # 分块处理
  for i in range(0, len(message), rate_bytes):
    block = message[i : i + rate_bytes]

    # 将块转换为 lanes
    block_lanes = bytes_to_lanes(block)

    # 与状态 XOR
    for x in range(5):
      for y in range(5):
        state[x][y] ^= block_lanes[x][y]

    # 应用 Keccak-f
    state = keccak_f(state)

  return state


def squeeze(state, output_bytes):
  """
  挤压阶段
  output_bytes: 输出的字节数
  """
  result = bytearray()
  rate_bytes = RATE // 8

  while len(result) < output_bytes:
    # 从状态中提取字节
    state_bytes = lanes_to_bytes(state)
    result.extend(state_bytes[: min(rate_bytes, output_bytes - len(result))])

    if len(result) < output_bytes:
      state = keccak_f(state)

  return bytes(result)


# ========== 主函数 ==========
def sha3_256(message):
  """
  SHA3-256 主函数
  输入: bytes
  输出: 32字节的哈希值
  """
  # 初始化状态 (全0)
  state = [[0] * 5 for _ in range(5)]

  # 填充消息
  padded_msg = pad_message(message)

  # 吸收阶段
  state = absorb(state, padded_msg)

  # 挤压阶段 (256 bits = 32 bytes)
  return squeeze(state, 32)


def sha3_256_hex(message):
  """返回十六进制字符串形式的哈希值"""
  return sha3_256(message).hex()


# ========== 测试函数 ==========
def test_sha3_256():
  """测试函数，验证实现正确性"""
  test_cases = [
    (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    (b"hello", "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"),
    (
      b"The quick brown fox jumps over the lazy dog",
      "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
    ),
    (
      b"The quick brown fox jumps over the lazy dog.",
      "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
    ),
    (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
  ]

  print("Testing SHA3-256 implementation:")
  print("=" * 70)

  all_passed = True
  for i, (input_msg, expected) in enumerate(test_cases, 1):
    result = sha3_256_hex(input_msg)
    passed = result == expected
    all_passed = all_passed and passed

    status = "✓" if passed else "✗"
    print(f"Test {i}: {status}")
    print(f"  Input:    {input_msg[:50]}{'...' if len(input_msg) > 50 else ''}")
    print(f"  Expected: {expected}")
    print(f"  Got:      {result}")

    if not passed:
      print("  MISMATCH!")
    print()

  if all_passed:
    print("All tests passed! ✓")
  else:
    print("Some tests failed! ✗")

  return all_passed


def benchmark():
  """简单的性能测试"""
  import time

  # 测试不同大小的数据
  test_sizes = [1, 100, 1000, 10000, 100000]  # bytes

  print("Benchmarking SHA3-256:")
  print("=" * 70)

  for size in test_sizes:
    data = b"A" * size

    # 预热
    sha3_256(b"warmup")

    # 计时
    start = time.time()
    iterations = max(1, 1000000 // max(size, 1))

    for _ in range(iterations):
      sha3_256(data)

    elapsed = time.time() - start
    speed = (size * iterations) / elapsed / 1024 / 1024  # MB/s

    print(
      f"Size: {size:7d} bytes | "
      f"Time: {elapsed / iterations * 1000:6.3f} ms/op | "
      f"Speed: {speed:6.2f} MB/s"
    )


# ========== 使用示例 ==========
if __name__ == "__main__":
  # 运行测试
  test_sha3_256()

  print("\n" + "=" * 70 + "\n")

  # 示例用法
  messages = [
    b"Hello, World!",
    b"Python SHA3-256 implementation",
    b"1234567890" * 10,
  ]

  print("Example usage:")
  for msg in messages:
    digest = sha3_256_hex(msg)
    print(f"SHA3-256('{msg[:20]}{'...' if len(msg) > 20 else ''}'):")
    print(f"  {digest}")
    print()

  # 可选: 运行性能测试
  # benchmark()
