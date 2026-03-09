#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2026/1/6 13:28
# @name    : base64.py
# @author  : azwpayne
# @desc    :
import random

from loguru import logger

B64_SOURCE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def base64_encode(data: bytes) -> str:
    """
    将bytes编码为base64字符串
    :param data:
    :return:
    """
    if not isinstance(data, bytes):
        raise TypeError("输入必须是bytes")

    if not data:
        return ""

    # 将输入转换为二进制字符串
    binary_str = ''.join(f'{byte:08b}' for byte in data)

    # 按6位分组
    groups = [binary_str[i:i + 6] for i in range(0, len(binary_str), 6)]

    # result = []
    # for group in groups:
    #     if len(group) < 6:
    #         # 最后一组不足6位，补0
    #         group = group.ljust(6, '0')
    #     # 将6位二进制转为整数，对应字符表
    #     index = int(group, 2)
    #     result.append(B64_CHARS[index])

    # 将6位二进制组转换为字符
    result = [B64_CHARS[int(group.ljust(6, '0'), 2)] for group in groups]

    # 计算需要填充的等号数量
    padding = (3 - len(data) % 3) % 3
    result.extend(['='] * padding)

    return ''.join(result)


def base64_decode(b64_str: str) -> bytes:
    """将base64字符串解码为bytes"""
    if not b64_str:
        return b""

    # 移除填充字符
    b64_str = b64_str.rstrip('=')

    # 将base64字符转为索引值
    try:
        indices = [B64_CHARS.index(char) for char in b64_str]
    except KeyError:
        raise ValueError("包含非法base64字符")

    # 将索引转为6位二进制
    binary_str = ''.join(f'{idx:06b}' for idx in indices)

    # 按8位分组（字节）
    byte_groups = [binary_str[i:i + 8] for i in range(0, len(binary_str), 8)]

    # 移除最后一组不完整的字节（如果有的话）
    if len(byte_groups[-1]) < 8:
        byte_groups = byte_groups[:-1]

    # 二进制字符串转bytes
    return bytes(int(group, 2) for group in byte_groups if len(group) == 8)


if __name__ == "__main__":
    test_cases = [
        b"hello",
        b"World",
        b"Python",
        b"base64",
        b"A",
        b"AB",
        b"ABC",
        b"base64 encode and decode",
        b"",
        b"a" * 100
    ]

    B64_CHARS = ''.join(random.sample(B64_SOURCE_CHARS, len(B64_SOURCE_CHARS))) \
        if random.randint(0, 1) \
        else B64_SOURCE_CHARS

    logger.info(f"是否使用原始的字符表: {B64_CHARS == B64_SOURCE_CHARS}, 当前字符串表: {B64_CHARS}")

    for test in test_cases:
        encoded = base64_encode(test)
        decoded = base64_decode(encoded)
        logger.debug(f"原文: {test}")
        logger.debug(f"编码: {encoded}")
        logger.debug(f"解码: {decoded}")
        logger.debug(f"验证: {test == decoded}\n")
