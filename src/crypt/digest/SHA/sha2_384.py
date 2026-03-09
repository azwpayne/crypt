#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
]

# 前 64 个素数的立方根小数部分常数
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


def _right_rotate(n: int, bits: int) -> int:
    """64位右循环移位"""
    return ((n >> bits) | (n << (64 - bits))) & 0xFFFFFFFFFFFFFFFF


def _maj(x: int, y: int, z: int) -> int:
    """ majority 函数: (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z) """
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
    message += b'\x80'  # 追加 1 位

    # 填充 0 直到长度 ≡ 112 mod 128
    while (len(message) % 128) != 112:
        message += b'\x00'

    # 追加 128 位消息长度（大端序）
    message += msg_len.to_bytes(16, 'big')
    return message


def _process_block(block: bytes, h: list) -> list:
    """
    处理单个 1024 位消息块
    block: 128 字节消息块
    h: 8 个 64 位哈希值组成的列表
    """
    # 消息调度：将 1024 位块扩展为 80 个 64 位字
    w = [int.from_bytes(block[i:i + 8], 'big') for i in range(0, 128, 8)]
    w += [0] * (80 - 16)

    for t in range(16, 80):
        w[t] = (_gamma1(w[t - 2]) + w[t - 7] + _gamma0(w[t - 15]) + w[t - 16]) & 0xFFFFFFFFFFFFFFFF

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
    return [(x + y) & 0xFFFFFFFFFFFFFFFF for x, y in zip([a, b, c, d, e, f, g, h0], h)]


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
        block = padded_message[i:i + 128]
        hash_values = _process_block(block, hash_values)

    # 输出：将 8 个 64 位字连接并截断为 384 位（前 6 个字）
    digest = b''.join(h.to_bytes(8, 'big') for h in hash_values[:6])
    return digest


def sha384_hex(message: bytes) -> str:
    """
    返回十六进制格式的 SHA-384 哈希值
    """
    return sha384(message).hex()


# 测试向量
def _run_tests():
    """NIST 测试向量验证"""
    test_cases = [
        (b"",
         "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
        (b"abc",
         "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")
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
    print(f"Large message test (1M 'a'): {'✓' if result_large == expected_large else '✗'}")


if __name__ == "__main__":
    _run_tests()
