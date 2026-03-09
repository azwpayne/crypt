# @time    : 2026/1/6 16:51
# @name    : sha3_256.py
# @author  : azwpayne
# @desc    :


import struct

# 常量定义
SHA3_256_RATE = 136  # 字节单位 (1088位)
SHA3_256_CAPACITY = 64  # 字节单位 (512位)
SHA3_256_OUTPUT_LENGTH = 32  # 字节单位 (256位)
KECCAK_F_WIDTH = 1600  # 位
KECCAK_F_ROUNDS = 24

# 轮常数 [7](@ref)
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

# 旋转偏移量 [7](@ref)
ROTATION_OFFSETS = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]

# π步骤的置换索引 [7](@ref)
PI_PERMUTATION = [
  0,
  6,
  12,
  18,
  24,
  3,
  9,
  10,
  16,
  22,
  1,
  7,
  13,
  19,
  20,
  4,
  5,
  11,
  17,
  23,
  2,
  8,
  14,
  15,
  21,
]


def rotate_left_64(x: int, n: int) -> int:
  """64位循环左移 [7](@ref)"""
  n = n % 64
  return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def bytes_to_lanes(data: bytes) -> int:
  """将字节数据转换为5x5的64位lane数组 [6](@ref)"""
  lanes = [0] * 25
  for i in range(min(len(data) // 8, 25)):
    lanes[i] = struct.unpack("<Q", data[i * 8 : (i + 1) * 8])[0]
  return lanes


def lanes_to_bytes(lanes: list[int]) -> bytes:
  """将5x5的64位lane数组转换为字节数据 [6](@ref)"""
  result = bytearray()
  for lane in lanes:
    result.extend(struct.pack("<Q", lane))
  return bytes(result)


def keccak_f_1600(state: list[int]) -> list[int]:
  """Keccak-f[1600]置换函数 [6,7](@ref)"""
  A = [[0] * 5 for _ in range(5)]

  # 将一维状态数组转换为5x5矩阵
  for x in range(5):
    for y in range(5):
      A[x][y] = state[x + 5 * y]

  # 24轮置换 [6](@ref)
  for round in range(KECCAK_F_ROUNDS):
    # θ步骤 [7](@ref)
    C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
    D = [C[(x - 1) % 5] ^ rotate_left_64(C[(x + 1) % 5], 1) for x in range(5)]

    for x in range(5):
      for y in range(5):
        A[x][y] ^= D[x]

    # ρ和π步骤 [7](@ref)
    B = [[0] * 5 for _ in range(5)]
    for x in range(5):
      for y in range(5):
        B[y][(2 * x + 3 * y) % 5] = rotate_left_64(A[x][y], ROTATION_OFFSETS[x][y])

    # χ步骤 [7](@ref)
    for x in range(5):
      for y in range(5):
        A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

    # ι步骤 [7](@ref)
    A[0][0] ^= RC[round]

  # 将5x5矩阵转换回一维状态数组
  result = [0] * 25
  for x in range(5):
    for y in range(5):
      result[x + 5 * y] = A[x][y]

  return result


def sha3_pad(message_len: int, rate: int) -> bytes:
  """SHA3填充函数 [6,8](@ref)"""
  # 计算需要填充的字节数
  pad_len = rate - (message_len % rate)
  if pad_len == 0:
    pad_len = rate

  # 创建填充字节
  padding = bytearray(pad_len)
  padding[0] = 0x06  # SHA3特定的域分隔符 [6](@ref)
  padding[pad_len - 1] |= 0x80  # 多比特率填充的结束标记 [6](@ref)

  return bytes(padding)


def sha3_256(msg: bytes) -> bytes:
  """SHA3-256哈希函数主实现 [1,8](@ref)"""
  # 初始化状态矩阵（全零）[8](@ref)
  state = [0] * 25

  # 消息填充 [6,8](@ref)
  padded_msg = msg + sha3_pad(len(msg), SHA3_256_RATE)

  # 吸收阶段 [8](@ref)
  for i in range(0, len(padded_msg), SHA3_256_RATE):
    block = padded_msg[i : i + SHA3_256_RATE]
    block_lanes = bytes_to_lanes(block.ljust(200, b"\x00"))

    # 将块与状态进行异或 [8](@ref)
    for j in range(len(block_lanes)):
      state[j] ^= block_lanes[j]

    # 应用Keccak-f置换 [6](@ref)
    state = keccak_f_1600(state)

  # 挤压阶段 [8](@ref)
  output = bytearray()
  while len(output) < SHA3_256_OUTPUT_LENGTH:
    output.extend(lanes_to_bytes(state)[:SHA3_256_RATE])
    if len(output) < SHA3_256_OUTPUT_LENGTH:
      state = keccak_f_1600(state)

  return bytes(output)[:SHA3_256_OUTPUT_LENGTH]


def sha3_256_hex(msg: bytes) -> str:
  """返回SHA3-256的十六进制字符串表示"""
  return sha3_256(msg).hex()


# 测试函数
def test_sha3_256():
  """测试函数验证实现的正确性 [9](@ref)"""
  test_vectors = [
    (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    (
      b"hello world",
      "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
    ),
  ]

  print("Testing SHA3-256 implementation:")
  all_passed = True

  for i, (msg, expected) in enumerate(test_vectors):
    result = sha3_256_hex(msg)
    passed = result == expected
    all_passed = all_passed and passed

    print(f"Test {i + 1}: {passed}")
    print(f"  Input:    {msg}")
    print(f"  Expected: {expected}")
    print(f"  Got:      {result}")
    print()

  if all_passed:
    print("All tests passed! ✅")
  else:
    print("Some tests failed! ❌")

  return all_passed


if __name__ == "__main__":
  # 运行测试
  test_sha3_256()

  # 示例用法
  message = b"Hello, SHA3-256!"
  hash_result = sha3_256_hex(message)
  print(f"SHA3-256('{message.decode()}') = {hash_result}")
