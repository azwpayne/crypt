#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2026/1/10 08:03
# @name    : base85.py
# @author  : azwpayne
# @desc    :

import struct

# Base85字符集 (RFC 1924版本，也用于Adobe ASCII85)
BASE85_ALPHABET = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"
DECODING_TABLE = {c: i for i, c in enumerate(BASE85_ALPHABET)}


def b85encode(data: bytes) -> str:
    """
    将字节数据编码为Base85字符串
    """
    if not data:
        return ""

    result = []
    padding = 0

    # 处理4字节一组
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]

        if len(chunk) < 4:
            padding = 4 - len(chunk)
            # 填充0使成为4字节
            chunk = chunk + b'\x00' * padding

        # 将4字节转换为32位整数
        value = struct.unpack('>I', chunk)[0]

        # 转换为5个Base85字符
        encoded_chars = []
        for _ in range(5):
            encoded_chars.append(BASE85_ALPHABET[value % 85])
            value //= 85
        encoded_chars.reverse()

        # 如果有填充，去掉相应数量的字符
        if padding:
            encoded_chars = encoded_chars[:-padding]

        result.extend(encoded_chars)

    return ''.join(result)


def b85decode(encoded: str) -> bytes:
    """
    将Base85字符串解码为字节数据
    """
    if not encoded:
        return b""

    # 移除可能存在的空格和换行
    encoded = encoded.strip()

    # 处理Adobe ASCII85的结束标记
    if encoded.endswith('~>'):
        encoded = encoded[:-2]

    result = bytearray()
    padding = 0

    # 处理5字符一组
    for i in range(0, len(encoded), 5):
        chunk = encoded[i:i + 5]

        if len(chunk) < 5:
            padding = 5 - len(chunk)
            # 填充'u'使成为5字符
            chunk = chunk + 'u' * padding

        # 将5个Base85字符转换为32位整数
        value = 0
        for char in chunk:
            if char not in DECODING_TABLE:
                raise ValueError(f"Invalid Base85 character: {char}")
            value = value * 85 + DECODING_TABLE[char]

        # 将32位整数转换为4字节
        try:
            decoded_bytes = struct.pack('>I', value)
        except struct.error:
            raise ValueError("Invalid Base85 data")

        # 如果有填充，去掉相应数量的字节
        if padding:
            decoded_bytes = decoded_bytes[:4 - padding]

        result.extend(decoded_bytes)

    return bytes(result)


def b85encode_ascii85(data: bytes) -> str:
    """
    Adobe ASCII85编码（添加<~ ~>分隔符）
    """
    encoded = b85encode(data)
    return f"<~{encoded}~>"


def b85decode_ascii85(encoded: str) -> bytes:
    """
    Adobe ASCII85解码（处理<~ ~>分隔符）
    """
    encoded = encoded.strip()
    if encoded.startswith('<~') and encoded.endswith('~>'):
        encoded = encoded[2:-2]
    return b85decode(encoded)


# 测试函数
def test_base85():
    """测试Base85编码解码"""
    test_cases = [
        b"Hello",
        b"World",
        b"Base85 test!",
        b"1234567890",
        b"",
        b"A" * 10,
        b"\x00\x01\x02\x03\x04",
    ]

    print("Testing Base85 encoding/decoding:")
    print("-" * 50)

    for i, test_data in enumerate(test_cases):
        # 标准Base85
        encoded = b85encode(test_data)
        decoded = b85decode(encoded)

        # ASCII85格式
        ascii85_encoded = b85encode_ascii85(test_data)
        ascii85_decoded = b85decode_ascii85(ascii85_encoded)

        # 验证
        success1 = decoded == test_data
        success2 = ascii85_decoded == test_data

        print(f"Test {i + 1}:")
        print(f"  Original: {test_data!r}")
        print(f"  Base85: {encoded}")
        print(f"  ASCII85: {ascii85_encoded}")
        print(f"  Decoded correctly: {success1} / {success2}")
        print()


if __name__ == "__main__":
    # 运行测试
    test_base85()

    # 使用示例
    print("\n" + "=" * 50)
    print("Usage examples:")
    print("=" * 50)

    # 示例1: 基本编码解码
    data = b"Hello, Base85!"
    encoded = b85encode(data)
    decoded = b85decode(encoded)
    print(f"Example 1 - Basic:")
    print(f"  Data: {data}")
    print(f"  Encoded: {encoded}")
    print(f"  Decoded: {decoded}")
    print(f"  Match: {data == decoded}")
    print()

    # 示例2: ASCII85格式
    ascii85_encoded = b85encode_ascii85(data)
    ascii85_decoded = b85decode_ascii85(ascii85_encoded)
    print(f"Example 2 - ASCII85:")
    print(f"  Data: {data}")
    print(f"  ASCII85: {ascii85_encoded}")
    print(f"  Decoded: {ascii85_decoded}")
    print(f"  Match: {data == ascii85_decoded}")
    print()

    # 示例3: 二进制数据
    binary_data = bytes(range(256))
    encoded_binary = b85encode(binary_data[:20])  # 只编码前20字节
    print(f"Example 3 - Binary data (first 20 bytes):")
    print(f"  Encoded: {encoded_binary}")
