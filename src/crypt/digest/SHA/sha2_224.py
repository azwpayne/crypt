#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2026/1/6 16:36
# @name    : sha2_224.py
# @author  : azwpayne
# @desc    :

import struct
from typing import List, Tuple

# ==================== 常量定义 ====================

# SHA256常量K（前64个质数立方根的小数部分前32位）
K: List[int] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# SHA224初始哈希值（前8个质数平方根的小数部分前32位，并进行修改）
H0_SHA224: List[int] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
]


# ==================== 位运算函数 ====================

def rotr(x: int, n: int, bits: int = 32) -> int:
    """循环右移：Rotate right (circular right shift)"""
    return ((x >> n) | (x << (bits - n))) & 0xFFFFFFFF


def sigma0(x: int) -> int:
    """Σ0(x) = ROTR(2, x) XOR ROTR(13, x) XOR ROTR(22, x)"""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def sigma1(x: int) -> int:
    """Σ1(x) = ROTR(6, x) XOR ROTR(11, x) XOR ROTR(25, x)"""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def gamma0(x: int) -> int:
    """σ0(x) = ROTR(7, x) XOR ROTR(18, x) XOR SHR(3, x)"""
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def gamma1(x: int) -> int:
    """σ1(x) = ROTR(17, x) XOR ROTR(19, x) XOR SHR(10, x)"""
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def ch(x: int, y: int, z: int) -> int:
    """Ch(x, y, z) = (x ∧ y) XOR (¬x ∧ z)"""
    return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
    """Maj(x, y, z) = (x ∧ y) XOR (x ∧ z) XOR (y ∧ z)"""
    return (x & y) ^ (x & z) ^ (y & z)


# ==================== 消息处理函数 ====================

def pad_message(message: bytes) -> bytes:
    """
    填充消息：添加1比特，然后补0，最后追加64位原始消息长度
    总长度 ≡ 448 (mod 512)
    """
    msg_len = len(message) * 8  # 原始消息长度（比特）

    # 添加1比特（0x80），然后填充0到合适长度
    padding = b'\x80'  # 1比特

    # 计算需要填充的0字节数
    # 目标长度：(len(message) + 1 + 8) % 64 == 56
    zero_len = (56 - (len(message) + 1) % 64) % 64
    padding += b'\x00' * zero_len

    # 追加64位原始消息长度（大端序）
    padding += struct.pack('>Q', msg_len)

    return message + padding


def parse_message(padded: bytes) -> List[List[int]]:
    """
    将填充后的消息解析为16个32位字的块列表
    每个块是包含16个整数的列表
    """
    return [
        [struct.unpack('>I', padded[i + j:i + j + 4])[0] for j in range(0, 64, 4)]
        for i in range(0, len(padded), 64)
    ]


def schedule(block: List[int]) -> List[int]:
    """
    从16字的块生成64字的消息调度
    使用函数式递归而非循环
    """

    def extend(w: List[int], t: int) -> List[int]:
        if t >= 64:
            return w
        s0 = gamma0(w[t - 15])
        s1 = gamma1(w[t - 2])
        new_word = (w[t - 16] + s0 + w[t - 7] + s1) & 0xFFFFFFFF
        return extend(w + [new_word], t + 1)

    return extend(block[:16], 16)


def compress_block(
        state: List[int],
        block: List[int],
        k_values: List[int]
) -> List[int]:
    """
    压缩单个512位块
    纯函数实现，不修改原始状态
    """
    # 初始化工作变量
    a, b, c, d, e, f, g, h = state

    def round_iter(
            ws: List[int],
            ks: List[int],
            a: int,
            b: int,
            c: int,
            d: int,
            e: int,
            f: int,
            g: int,
            h: int
    ) -> Tuple[int, int, int, int, int, int, int, int]:
        """递归处理64轮"""
        if not ws:
            return a, b, c, d, e, f, g, h

        w, *ws_rest = ws
        k, *ks_rest = ks

        # 计算轮函数
        t1 = (h + sigma1(e) + ch(e, f, g) + k + w) & 0xFFFFFFFF
        t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF

        # 更新工作变量
        new_h = g
        new_g = f
        new_f = e
        new_e = (d + t1) & 0xFFFFFFFF
        new_d = c
        new_c = b
        new_b = a
        new_a = (t1 + t2) & 0xFFFFFFFF

        return round_iter(ws_rest, ks_rest, new_a, new_b, new_c, new_d, new_e, new_f, new_g, new_h)

    # 生成消息调度
    w_schedule = schedule(block)

    # 执行64轮压缩
    a, b, c, d, e, f, g, h = round_iter(w_schedule, k_values, a, b, c, d, e, f, g, h)

    # 更新哈希值
    return [
        (a + state[0]) & 0xFFFFFFFF,
        (b + state[1]) & 0xFFFFFFFF,
        (c + state[2]) & 0xFFFFFFFF,
        (d + state[3]) & 0xFFFFFFFF,
        (e + state[4]) & 0xFFFFFFFF,
        (f + state[5]) & 0xFFFFFFFF,
        (g + state[6]) & 0xFFFFFFFF,
        (h + state[7]) & 0xFFFFFFFF,
    ]


# ==================== 主函数 ====================

def sha224(message: bytes) -> bytes:
    """
    纯函数式SHA224实现

    参数:
        message: 输入消息(bytes)

    返回:
        224位哈希值(bytes)
    """
    # 1. 填充消息
    padded = pad_message(message)

    # 2. 解析消息块
    blocks = parse_message(padded)

    # 3. 处理每个块
    final_state = [H0_SHA224] * 1  # 初始状态包装

    def process_blocks(state: List[int], blocks: List[List[int]]) -> List[int]:
        """递归处理所有块"""
        if not blocks:
            return state

        block, *remaining = blocks
        new_state = compress_block(state, block, K)
        return process_blocks(new_state, remaining)

    # 执行压缩
    hash_state = process_blocks(H0_SHA224[:], blocks)

    # 4. 截断为224位（取前7个字）
    truncated = hash_state[:7]

    # 5. 转换为字节（大端序）
    return b''.join(struct.pack('>I', word) for word in truncated)


# ==================== 辅助函数 ====================

def sha224_hex(message: bytes) -> str:
    """返回SHA224的十六进制字符串表示"""
    return sha224(message).hex()


# ==================== 测试用例 ====================

def run_tests():
    """测试向量验证（来自NIST标准）"""
    test_cases = [
        (b"", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
        (b"abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"),
    ]

    for msg, expected in test_cases:
        result = sha224_hex(msg)
        print(f"消息: {msg!r}")
        print(f"结果: {result}")
        print(f"期望: {expected}")
        print(f"验证: {'✓' if result == expected else '✗'}\n")


if __name__ == '__main__':
    run_tests()
