#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2025/12/24 13:30
# @name    : sha2_512_256.py
# @author  : azwpayne
# @desc    :

# -*- coding: utf-8 -*-
"""
SHA-512/256 纯Python实现
遵循FIPS 180-4标准，输出256位摘要
"""

from typing import List, Union

# 初始哈希值 (前32位与SHA-256相同，但为64位表示)
INITIAL_HASH_VALUES = [
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
    0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
]

# 常量K (前80个质数立方根的小数部分)
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
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
    padding = b'\x80' + b'\x00' * ((112 - (msg_len + 1) % 128) % 128)

    # 附加64位消息长度（大端序）
    return message + padding + bit_len.to_bytes(16, 'big')


def process_chunk(chunk: bytes, h: List[int]) -> List[int]:
    """处理一个128字节的消息块"""
    # 创建消息调度数组
    w = [0] * 80

    # 前16个字来自消息块（64位大端序）
    for i in range(16):
        w[i] = int.from_bytes(chunk[i * 8:(i + 1) * 8], 'big')

    # 扩展消息调度
    for i in range(16, 80):
        w[i] = (gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFFFFFFFFFF

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


def sha512_256(message: Union[bytes, str], encoding: str = 'utf-8') -> str:
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
        chunk = padded_message[i:i + 128]
        h = process_chunk(chunk, h)

    # 截取前256位（4个64位字）
    digest = b''.join(val.to_bytes(8, 'big') for val in h[:4])

    return digest.hex()


# 使用示例
if __name__ == '__main__':
    # 测试向量来自NIST
    test_cases = [
        (b"", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"),
        (b"abc", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
         "835f9207766637f832cb3022f9d386b8b9426876f398d6b013a4925cc752806d"),
    ]

    for msg, expected in test_cases:
        result = sha512_256(msg)
        print(f"消息: {msg[:50]}{'...' if len(msg) > 50 else ''}")
        print(f"结果: {result}")
        print(f"正确: {'✓' if result == expected else '✗'}")
        print()
