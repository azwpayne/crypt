#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2025/12/24 13:28
# @name    : Chacha20.py
# @author  : azwpayne
# @desc    :


import struct


def rotl(v, n):
    """对32位无符号整数 v 进行循环左移 n 位。"""
    return ((v << n) & 0xffffffff) | (v >> (32 - n))


def quarter_round(x, a, b, c, d):
    """
    ChaCha20 的四分轮函数，对状态数组 x 的 a, b, c, d 四个位置进行操作。
    """
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotl(x[b] ^ x[c], 7)


def chacha20_block(key, counter, nonce):
    # ChaCha20 常量 "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<3I", nonce))

    # 构造初始状态，共16个32位整数
    state = [0] * 16
    state[0:4] = constants
    state[4:12] = key_words
    state[12] = counter & 0xffffffff
    state[13:16] = nonce_words

    working_state = state.copy()

    # 进行 20 轮运算（10 次双轮，每次包括列轮和对角线轮）
    for _ in range(10):
        # 列轮
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        # 对角线轮
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    # 最终将原始状态与运算结果相加
    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xffffffff

    # 将 16 个 32 位整数以小端序打包成 64 字节
    return struct.pack("<16L", *working_state)


def chacha20_encrypt(key, nonce, counter, plaintext):
    ciphertext = bytearray()
    # 每个块 64 字节，若明文长度不足 64 字节，则只使用部分 keystream
    block_count = (len(plaintext) + 63) // 64
    for i in range(block_count):
        keystream = chacha20_block(key, counter + i, nonce)
        block = plaintext[i * 64:(i + 1) * 64]
        # 异或运算
        for j in range(len(block)):
            ciphertext.append(block[j] ^ keystream[j])
    return bytes(ciphertext)


# 示例：加密和解密测试
# 明文: 30313233343536373839
# 密文 (hex): a3e365d72defcc690ef2
# 解密后明文: 30313233343536373839
if __name__ == '__main__':
    # 示例密钥（32字节）和 nonce（12字节）
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    nonce = bytes.fromhex('202122232425262728292a2b')
    counter = 0  # 一直都是
    plaintext = bytes.fromhex('30313233343536373839')
    print("明文:", plaintext.hex())

    # 加密
    ciphertext = chacha20_encrypt(key, nonce, counter, plaintext)
    print("密文 (hex):", ciphertext.hex())

    # 解密：对密文再次使用同样的 keystream 异或即可还原明文
    decrypted = chacha20_encrypt(key, nonce, counter, ciphertext)  #
    print("解密后明文:", decrypted.hex())
