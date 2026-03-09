#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2026/1/6 16:50
# @name    : sha3_224.py
# @author  : azwpayne
# @desc    :

# SHA3-224实现
# 符合FIPS 202标准

# 常量定义
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

ROTATION_CONSTANTS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]


def rotate_left(x, n, w=64):
    """循环左移，w为字长(64位)"""
    return ((x << (n % w)) | (x >> (w - (n % w)))) & ((1 << w) - 1)


def keccak_f_1600(state):
    """Keccak-f[1600]置换函数"""
    w = 64
    for round_num in range(24):
        # θ步骤
        C = [0] * 5
        D = [0] * 5

        for x in range(5):
            C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]

        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ rotate_left(C[(x + 1) % 5], 1, w)

        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]

        # ρ和π步骤
        B = [[0] * 5 for _ in range(5)]

        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rotate_left(state[x][y], ROTATION_CONSTANTS[x][y], w)

        # χ步骤
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

        # ι步骤
        state[0][0] ^= RC[round_num]

    return state


def bytes_to_lanes(message_bytes):
    """将字节转换为5x5状态矩阵(64位字)"""
    state = [[0] * 5 for _ in range(5)]

    for i in range(len(message_bytes)):
        byte = message_bytes[i]
        x = (i // 8) % 5
        y = (i // 40) % 5
        state[x][y] ^= (byte << (8 * (i % 8)))

    return state


def lanes_to_bytes(state):
    """将5x5状态矩阵转换为字节序列"""
    output = bytearray()

    for y in range(5):
        for x in range(5):
            lane = state[x][y]
            for i in range(8):
                output.append((lane >> (8 * i)) & 0xFF)

    return bytes(output)


def keccak_pad(message, rate_bits):
    """SHA3填充函数"""
    rate_bytes = rate_bits // 8
    message_len = len(message)

    # 添加后缀位: 01 (对于SHA3是0x06)
    padded = bytearray(message)
    padded.append(0x06)  # SHA3使用0x06 (二进制: 01 10)

    # 填充0直到长度为(rate_bytes - 1)的倍数
    while (len(padded) % rate_bytes) != (rate_bytes - 1):
        padded.append(0x00)

    # 最后添加结束位
    padded.append(0x80)

    return bytes(padded)


def keccak_sponge(input_bytes, capacity_bits, output_bits, delimiter=0x06):
    """Keccak海绵函数"""
    rate_bits = 1600 - capacity_bits
    rate_bytes = rate_bits // 8
    output_bytes = output_bits // 8

    # 填充输入
    padded_input = keccak_pad(input_bytes, rate_bits)

    # 初始化状态
    state = [[0] * 5 for _ in range(5)]

    # 吸收阶段
    for i in range(0, len(padded_input), rate_bytes):
        block = padded_input[i:i + rate_bytes]
        block_state = bytes_to_lanes(block)

        # 与状态异或
        for x in range(5):
            for y in range(5):
                state[x][y] ^= block_state[x][y]

        # 应用置换函数
        state = keccak_f_1600(state)

    # 挤压阶段
    output = bytearray()
    while len(output) < output_bytes:
        # 从状态中提取输出
        output_block = lanes_to_bytes(state)
        output.extend(output_block[:min(rate_bytes, output_bytes - len(output))])

        if len(output) < output_bytes:
            state = keccak_f_1600(state)

    return bytes(output[:output_bytes])


def sha3_224(message):
    """
    SHA3-224哈希函数
    message: 输入消息(字节串)
    返回: 224位(28字节)哈希值
    """
    # SHA3-224参数: capacity=448 bits, output=224 bits
    return keccak_sponge(message, 448, 224, delimiter=0x06)


def test_sha3_224():
    """测试函数，验证实现正确性"""
    test_cases = [
        (b"",
         bytes.fromhex("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")),
        (b"abc",
         bytes.fromhex("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")),
        (b"hello world",
         bytes.fromhex("dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5")),
        (b"The quick brown fox jumps over the lazy dog",
         bytes.fromhex("d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795")),
    ]

    print("Testing SHA3-224 implementation...")
    all_pass = True

    for i, (input_msg, expected) in enumerate(test_cases):
        result = sha3_224(input_msg)

        if result == expected:
            print(f"Test {i + 1} PASSED")
        else:
            print(f"Test {i + 1} FAILED")
            print(f"  Input:    {input_msg[:20]}..." if len(
                input_msg) > 20 else f"  Input:    {input_msg}")
            print(f"  Expected: {expected.hex()}")
            print(f"  Got:      {result.hex()}")
            all_pass = False

    if all_pass:
        print("\nAll tests passed! SHA3-224 implementation is correct.")
    else:
        print("\nSome tests failed!")

    return all_pass


def demo():
    """演示如何使用sha3_224函数"""
    messages = [
        b"",
        b"abc",
        b"hello world",
        b"The quick brown fox jumps over the lazy dog",
        b"Python SHA3-224 implementation",
    ]

    print("SHA3-224 Demo:")
    print("-" * 80)

    for msg in messages:
        hash_result = sha3_224(msg)
        print(f"Input:  {msg[:50]}{'...' if len(msg) > 50 else ''}")
        print(f"Output: {hash_result.hex()}")
        print(f"Length: {len(hash_result)} bytes ({len(hash_result) * 8} bits)")
        print("-" * 80)


if __name__ == "__main__":
    # 运行测试
    if test_sha3_224():
        print("\n" + "=" * 80)
        # 运行演示
        demo()