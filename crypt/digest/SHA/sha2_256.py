#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2025/12/24 13:31
# @name    : sha2_256.py
# @author  : azwpayne
# @desc    :


import struct


def right_rotate(value, shift_bits):
    """
    对32位整数进行右循环移位

    :param value: 要移位的32位整数
    :param shift_bits: 右移的位数
    :return: 循环移位后的32位整数
    """
    # 规范化移位位数到0-31范围内
    normalized_shift = shift_bits % 32
    # 如果移位位数为0，直接返回原值
    if normalized_shift == 0:
        return value & 0xFFFFFFFF
    # 执行右循环移位操作
    return ((value >> normalized_shift) | (value << (32 - normalized_shift))) & 0xFFFFFFFF


# 常量
K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
)
# 初始哈希值
H = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
)


def sha256(data):
    # 步骤 1: 填充消息
    original_byte_len = len(data)
    original_bit_len = original_byte_len * 8
    data += b'\x80'
    data += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    data += struct.pack('>Q', original_bit_len)

    # 步骤 2: 解析消息为512-bit块
    blocks = []
    for i in range(0, len(data), 64):
        blocks.append(data[i:i + 64])

    # 步骤 3: 初始化工作变量
    hash_pieces = H[:]

    # 步骤 4: 处理每一个块
    for block in blocks:
        W = list(struct.unpack('>16L', block)) + [0] * 48

        for i in range(16, 64):
            s0 = right_rotate(W[i - 15], 7) ^ right_rotate(W[i - 15], 18) ^ (W[i - 15] >> 3)
            s1 = right_rotate(W[i - 2], 17) ^ right_rotate(W[i - 2], 19) ^ (W[i - 2] >> 10)
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, h = hash_pieces

        for i in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)  # e
            ch = (e & f) ^ (~e & g)  # e f g
            temp1 = (h + S1 + ch + K[i] + W[i]) & 0xffffffff  # h

            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)  # a
            maj = (a & b) ^ (a & c) ^ (b & c)  # a b c
            temp2 = (S0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        hash_pieces = [(x + y) & 0xffffffff for x, y in zip(hash_pieces, [a, b, c, d, e, f, g, h])]
    # 步骤 5: 拼接哈希值
    return ''.join(f'{piece:08x}' for piece in hash_pieces)


# hash_value = sha256('yangruhua'.encode())
# print(f'SHA-256: {hash_value}')
if __name__ == '__main__':
    print(sha256("".encode("utf-8")))
    print(sha256("abc".encode("utf-8")))
