#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2026/1/6 16:51
# @name    : sha3_512.py.py
# @author  : azwpayne
# @desc    :

# !/usr/bin/env python3
"""
完全正确的SHA3-512纯Python实现
不依赖任何外部库，不使用面向对象
可与Python标准库hashlib.sha3_512进行对比验证
"""

# SHA3-512常量定义
RATE_BITS = 576
RATE_BYTES = RATE_BITS // 8
CAPACITY_BITS = 1024
HASH_LENGTH_BITS = 512
HASH_LENGTH_BYTES = HASH_LENGTH_BITS // 8
STATE_WIDTH = 5
LANE_SIZE_BITS = 64
LANE_SIZE_BYTES = LANE_SIZE_BITS // 8
STATE_SIZE_BYTES = 200  # 5 * 5 * 8

# 轮常数
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

# 旋转偏移量
RHO = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]

# π置换索引
PI = [
    (0, 0), (1, 3), (2, 1), (3, 4), (4, 2),
    (0, 1), (1, 4), (2, 2), (3, 0), (4, 3),
    (0, 2), (1, 0), (2, 3), (3, 1), (4, 4),
    (0, 3), (1, 1), (2, 4), (3, 2), (4, 0),
    (0, 4), (1, 2), (2, 0), (3, 3), (4, 1)
]


def rotl_64(x, n):
    """64位循环左移"""
    n = n % 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def load_64_le(b):
    """小端字节序加载64位整数"""
    return (b[0] |
            (b[1] << 8) |
            (b[2] << 16) |
            (b[3] << 24) |
            (b[4] << 32) |
            (b[5] << 40) |
            (b[6] << 48) |
            (b[7] << 56))


def store_64_le(x):
    """将64位整数存储为小端字节序"""
    return bytes([
        x & 0xFF,
        (x >> 8) & 0xFF,
        (x >> 16) & 0xFF,
        (x >> 24) & 0xFF,
        (x >> 32) & 0xFF,
        (x >> 40) & 0xFF,
        (x >> 48) & 0xFF,
        (x >> 56) & 0xFF
    ])


def keccak_f1600(state):
    """Keccak-f[1600]置换函数"""
    # 将状态转换为5x5的64位整数矩阵
    A = [[0] * 5 for _ in range(5)]

    # 从字节状态加载到矩阵
    for y in range(5):
        for x in range(5):
            idx = 8 * (5 * y + x)
            lane_bytes = state[idx:idx + 8]
            A[x][y] = load_64_le(lane_bytes)

    # 24轮置换
    for round_idx in range(24):
        # θ步骤
        C = [0] * 5
        D = [0] * 5

        for x in range(5):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]

        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ rotl_64(C[(x + 1) % 5], 1)

        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]

        # ρ和π步骤
        B = [[0] * 5 for _ in range(5)]

        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rotl_64(A[x][y], RHO[x][y])

        # χ步骤
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

        # ι步骤
        A[0][0] ^= RC[round_idx]

    # 将矩阵转换回字节状态
    new_state = bytearray(STATE_SIZE_BYTES)
    for y in range(5):
        for x in range(5):
            idx = 8 * (5 * y + x)
            lane_bytes = store_64_le(A[x][y])
            new_state[idx:idx + 8] = lane_bytes

    return bytes(new_state)


def keccak_absorb(state, data):
    """吸收数据到状态中"""
    new_state = bytearray(state)

    for i in range(len(data)):
        new_state[i] ^= data[i]

    return bytes(new_state)


def keccak_squeeze(state, output_length_bytes):
    """从状态中挤压输出"""
    output = bytearray()

    while len(output) < output_length_bytes:
        # 每次挤压一个完整的数据块
        block_size = min(RATE_BYTES, output_length_bytes - len(output))
        output.extend(state[:block_size])

        if len(output) < output_length_bytes:
            state = keccak_f1600(state)

    return bytes(output)


def sha3_512(message):
    """SHA3-512哈希函数"""
    # 初始化状态
    state = bytes([0] * STATE_SIZE_BYTES)

    # 1. 吸收阶段
    block_size = RATE_BYTES
    message_len = len(message)

    # 处理完整的数据块
    for i in range(0, message_len, block_size):
        block_end = min(i + block_size, message_len)
        block = message[i:block_end]

        if len(block) == block_size:
            # 完整块
            state = keccak_absorb(state, block)
            state = keccak_f1600(state)
        else:
            # 最后一个不完整的块
            padded_block = bytearray(block_size)
            padded_block[:len(block)] = block
            padded_block[len(block)] = 0x06  # SHA3填充：0x06
            padded_block[-1] |= 0x80  # SHA3填充：末尾设置0x80

            state = keccak_absorb(state, padded_block)
            state = keccak_f1600(state)

    # 如果消息长度正好是block_size的倍数，需要处理一个额外的填充块
    if message_len > 0 and message_len % block_size == 0:
        padded_block = bytearray(block_size)
        padded_block[0] = 0x06
        padded_block[-1] = 0x80

        state = keccak_absorb(state, padded_block)
        state = keccak_f1600(state)

    # 处理空消息的特殊情况
    if message_len == 0:
        padded_block = bytearray(block_size)
        padded_block[0] = 0x06
        padded_block[-1] = 0x80

        state = keccak_absorb(state, padded_block)
        state = keccak_f1600(state)

    # 2. 挤压阶段
    return keccak_squeeze(state, HASH_LENGTH_BYTES)


def sha3_512_hex(message):
    """返回十六进制字符串形式的SHA3-512哈希值"""
    return sha3_512(message).hex()


# ========== 测试和验证 ==========

def test_known_vectors():
    """测试已知的SHA3-512测试向量"""
    print("测试已知SHA3-512测试向量:")
    print("=" * 80)

    # 来自NIST的官方测试向量
    test_cases = [
        # (消息, 期望的SHA3-512哈希值)
        (b"",
         "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" +
         "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),

        (b"abc",
         "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" +
         "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),

        (b"The quick brown fox jumps over the lazy dog",
         "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff" +
         "23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450"),

        (b"The quick brown fox jumps over the lazy dog.",
         "18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597" +
         "bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8"),

    ]

    all_passed = True

    for i, (msg, expected) in enumerate(test_cases):
        result = sha3_512_hex(msg)
        passed = result == expected.lower()
        all_passed = all_passed and passed

        print(f"测试 {i + 1}:")
        print(f"  消息:    {msg[:20]}...")
        print(f"  期望:    {expected[:16]}...")
        print(f"  得到:    {result[:16]}...")
        print(f"  结果:    {'✓ 通过' if passed else '✗ 失败'}")

        if not passed:
            print(f"          完整期望: {expected}")
            print(f"          完整得到: {result}")

        print()

    return all_passed


def compare_with_hashlib():
    """与Python标准库hashlib的SHA3-512实现对比"""
    import hashlib

    print("与Python hashlib.sha3_512对比测试:")
    print("=" * 80)

    test_messages = [
        b"",
        b"a",
        b"abc",
        b"hello world",
        b"The quick brown fox jumps over the lazy dog",
        b"The quick brown fox jumps over the lazy dog.",
        b"1234567890" * 10,
        b"A" * 100,
        b"test message for sha3-512",
        b"Hello, SHA3-512! This is a test.",
    ]

    all_passed = True

    for i, msg in enumerate(test_messages):
        our_hash = sha3_512_hex(msg)
        std_hash = hashlib.sha3_512(msg).hexdigest()
        passed = our_hash == std_hash
        all_passed = all_passed and passed

        msg_display = msg[:30] if len(msg) <= 30 else msg[:27] + b"..."
        print(f"测试 {i + 1:2d}: {msg_display}")
        print(f"      我们的: {our_hash}")
        print(f"      标准库: {std_hash}")
        print(f"      结果:   {'✓ 相同' if passed else '✗ 不同'}")
        print()

    return all_passed


def test_edge_cases():
    """测试边界情况"""
    print("测试边界情况:")
    print("=" * 80)

    test_cases = [
        (b"", "空消息"),
        (b"a" * 1, "1字节"),
        (b"a" * 71, "71字节（刚好小于一个块）"),
        (b"a" * 72, "72字节（正好一个块）"),
        (b"a" * 73, "73字节（刚好超过一个块）"),
        (b"a" * 144, "144字节（正好两个块）"),
        (b"a" * 1000, "1000字节"),
        (bytes(range(256)), "0-255所有字节"),
    ]

    all_passed = True

    for msg, description in test_cases:
        our_hash = sha3_512_hex(msg)

        # 如果有hashlib，用hashlib验证
        try:
            import hashlib
            std_hash = hashlib.sha3_512(msg).hexdigest()
            passed = our_hash == std_hash
            verify = f" (与hashlib: {'✓' if passed else '✗'})"
        except:
            verify = ""

        print(f"{description:30s}: {our_hash[:16]}...{verify}")

        if 'passed' in locals():
            all_passed = all_passed and passed

    return all_passed


def run_comprehensive_test():
    """运行全面的测试"""
    print("SHA3-512实现综合测试")
    print("=" * 80)
    print()

    # 测试1: 已知测试向量
    test1_passed = test_known_vectors()
    print("已知测试向量测试:", "✓ 通过" if test1_passed else "✗ 失败")
    print()

    # 测试2: 与hashlib对比
    test2_passed = compare_with_hashlib()
    print("与hashlib对比测试:", "✓ 通过" if test2_passed else "✗ 失败")
    print()

    # 测试3: 边界情况测试
    test3_passed = test_edge_cases()
    print("边界情况测试:", "✓ 通过" if test3_passed else "✗ 失败")
    print()

    # 最终结果
    print("=" * 80)
    if test1_passed and test2_passed and test3_passed:
        print("所有测试通过！实现完全正确。✓")
        return True
    else:
        print("测试失败！实现有问题。✗")
        return False


# 简单的自包含测试，不依赖hashlib
def self_contained_test():
    """自包含测试，不依赖hashlib"""
    print("自包含测试（不依赖hashlib）:")
    print("=" * 80)

    # 测试空字符串
    empty_hash = sha3_512_hex(b"")
    expected_empty = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" + \
                     "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"

    print(f"空字符串测试: {'✓' if empty_hash == expected_empty else '✗'}")
    print(f"  得到: {empty_hash}")
    print(f"  期望: {expected_empty}")
    print()

    # 测试"abc"
    abc_hash = sha3_512_hex(b"abc")
    expected_abc = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" + \
                   "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"

    print(f"'abc'测试: {'✓' if abc_hash == expected_abc else '✗'}")
    print(f"  得到: {abc_hash}")
    print(f"  期望: {expected_abc}")

    return empty_hash == expected_empty and abc_hash == expected_abc


def example_usage():
    """使用示例"""
    print("使用示例:")
    print("=" * 80)

    # 示例1: 哈希字符串
    message = "Hello, SHA3-512!"
    hash_hex = sha3_512_hex(message.encode('utf-8'))
    print(f"消息: '{message}'")
    print(f"SHA3-512: {hash_hex}")
    print()

    # 示例2: 哈希文件内容
    print("模拟文件哈希:")
    file_content = b"This is a test file content.\n" + b"Second line of the file.\n" + b"Third line."
    file_hash = sha3_512_hex(file_content)
    print(f"文件内容: {len(file_content)} 字节")
    print(f"文件SHA3-512: {file_hash}")
    print()

    # 示例3: 验证数据完整性
    original_data = b"Important data that must not be tampered with"
    original_hash = sha3_512_hex(original_data)

    tampered_data = b"Important data that must be tampered with"
    tampered_hash = sha3_512_hex(tampered_data)

    print("数据完整性验证:")
    print(f"原始数据: {original_data[:30]}...")
    print(f"原始哈希: {original_hash}")
    print(f"篡改数据: {tampered_data[:30]}...")
    print(f"篡改哈希: {tampered_hash}")
    print(f"哈希是否相同: {original_hash == tampered_hash}")


if __name__ == "__main__":
    # 首先运行自包含测试
    if self_contained_test():
        print("\n自包含测试通过！✓")
        print("=" * 80)
        print()

        # 如果有hashlib，运行全面测试
        try:
            import hashlib

            print("检测到hashlib，运行全面对比测试...")
            print()

            if run_comprehensive_test():
                print("\n实现验证完成！可以安全使用。")
                print()
                example_usage()
            else:
                print("\n实现存在问题，请检查代码。")
        except ImportError:
            print("未找到hashlib，跳过全面测试。")
            print()
            example_usage()
    else:
        print("\n自包含测试失败！实现有严重问题。")
