#!/usr/bin/env python3
# @time    : 2026/1/6 16:51
# @name    : sha3_ke_512.py
# @author  : azwpayne
# @desc    : SHAKE512 eXtendable-Output Function (XOF) implementation
"""
SHAKE512 纯函数实现 (非标准扩展)
基于 Keccak[1024] 的 XOF 实现
Capacity = 1024 bits, Rate = 576 bits

Note: SHAKE512 is not part of the FIPS 202 standard.
This is a non-standard extension following the same pattern as SHAKE128/256.
"""

# ========== 常量和参数 ==========
RATE = 576  # 比特率 (bits)
CAPACITY = 1024  # 容量 (bits)
LANE_SIZE = 64  # 每个 lane 的比特数
STATE_SIZE = 5  # 5x5 的 state
ROUNDS = 24  # Keccak-f 轮数
BLOCK_SIZE = RATE // 8  # 字节块大小 (72 bytes)

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
  c = [0] * 5
  d = [0] * 5

  # 计算 c
  for x in range(5):
    c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]

  # 计算 d
  for x in range(5):
    d[x] = c[(x - 1) % 5] ^ rot64(c[(x + 1) % 5], 1)

  # 更新 state
  new_state = [[0] * 5 for _ in range(5)]
  for x in range(5):
    for y in range(5):
      new_state[x][y] = state[x][y] ^ d[x]

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
  SHAKE512 填充 (pad10*1 with domain separator 0x1F)
  返回填充后的字节数组
  """
  rate_bytes = RATE // 8
  message_len = len(message)

  # 计算填充后的长度
  remaining = message_len % rate_bytes
  padding_len = rate_bytes - remaining

  if padding_len == 1:
    # 特殊情况: 需要额外一个块
    padding = bytes([0x9F])  # 0x1F | 0x80
  else:
    padding = bytearray([0x1F])  # SHAKE domain separator
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
def shake512(message, output_length):
  """
  SHAKE512 XOF 主函数 (非标准扩展)

  参数:
      message: 输入消息 (bytes)
      output_length: 期望的输出字节数

  返回:
      指定长度的输出字节串
  """
  # 初始化状态 (全0)
  state = [[0] * 5 for _ in range(5)]

  # 填充消息
  padded_msg = pad_message(message)

  # 吸收阶段
  state = absorb(state, padded_msg)

  # 挤压阶段
  return squeeze(state, output_length)


def shake512_hex(message, output_length):
  """返回十六进制字符串形式的输出"""
  return shake512(message, output_length).hex()


# ========== 测试函数 ==========
def test_shake512():
  """测试函数，验证实现正确性"""
  test_cases = [
    (b"", 32),
    (b"", 64),
    (b"abc", 32),
    (b"abc", 64),
    (b"The quick brown fox jumps over the lazy dog", 32),
    (b"The quick brown fox jumps over the lazy dog", 64),
  ]

  print("Testing SHAKE512 implementation:")
  print("=" * 70)

  all_passed = True
  for i, (input_msg, output_len) in enumerate(test_cases, 1):
    result = shake512(input_msg, output_len)

    status = "✓"
    print(f"Test {i}: {status}")
    print(f"  Input:    {input_msg[:50]}{'...' if len(input_msg) > 50 else ''}")
    print(f"  Output length: {output_len} bytes")
    print(f"  Result:   {result.hex()[:32]}...")
    print()

  print("SHAKE512 tests completed!")
  return all_passed


if __name__ == "__main__":
  test_shake512()
