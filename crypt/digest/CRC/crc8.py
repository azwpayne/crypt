#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2026/1/6 16:04
# @name    : crc8.py
# @author  : azwpayne
# @desc    :

def crc8(data: bytes, poly: int = 0x07, init: int = 0x00,
         ref_in: bool = False, ref_out: bool = False, xor_out: int = 0x00) -> int:
    """
    通用CRC8计算函数 - 支持所有标准参数

    参数:
        data: 输入字节数据 (bytes类型)
        poly: 多项式 (例如 0x07, 0x31, 0xA7)
        init: 初始值 (通常为 0x00 或 0xFF)
        ref_in: 输入是否按位反转 (boolean)
        ref_out: 输出是否按位反转 (boolean)
        xor_out: 最终异或值 (通常为 0x00 或 0xFF)

    返回:
        CRC8校验值 (0-255)
    """

    # 生成CRC查找表
    crc_table = [0] * 256
    for i in range(256):
        crc = i
        for j in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFF  # 保持8位
        crc_table[i] = crc

    # 初始化CRC值
    crc = init

    # 处理每个字节
    for byte in data:
        if ref_in:
            # 输入字节按位反转
            byte = reverse_bits(byte)

        # 查表计算
        crc = crc_table[crc ^ byte]

    # 输出处理
    if ref_out:
        crc = reverse_bits(crc)

    return crc ^ xor_out


def reverse_bits(byte: int) -> int:
    """8位按位反转"""
    bit_reversed = 0
    for i in range(8):
        bit_reversed <<= 1
        bit_reversed |= (byte & 1)
        byte >>= 1
    return bit_reversed


# ============= 预定义的标准CRC8变体 =============

def crc8_maxim(data: bytes) -> int:
    """
    CRC-8/MAXIM (又称 DOW-CRC)
    poly=0x31 init=0x00 refin=true refout=true xorout=0x00
    用于Maxim 1-Wire设备
    """
    return crc8(data, poly=0x31, init=0x00, ref_in=True, ref_out=True, xor_out=0x00)


def crc8_autosar(data: bytes) -> int:
    """
    CRC-8/AUTOSAR
    poly=0x2F init=0xFF refin=false refout=false xorout=0xFF
    汽车电子标准
    """
    return crc8(data, poly=0x2F, init=0xFF, ref_in=False, ref_out=False, xor_out=0xFF)


def crc8_lte(data: bytes) -> int:
    """
    CRC-8/LTE
    poly=0x9B init=0x00 refin=false refout=false xorout=0x00
    移动通信标准
    """
    return crc8(data, poly=0x9B, init=0x00, ref_in=False, ref_out=False, xor_out=0x00)


def crc8_smbus(data: bytes) -> int:
    """
    CRC-8/SMBUS (又称 CRC-8/CCITT)
    poly=0x07 init=0x00 refin=false refout=false xorout=0x00
    系统管理总线
    """
    return crc8(data, poly=0x07, init=0x00, ref_in=False, ref_out=False, xor_out=0x00)


def crc8_bluetooth(data: bytes) -> int:
    """
    CRC-8/BLUETOOTH
    poly=0xA7 init=0x00 refin=true refout=true xorout=0x00
    蓝牙头部错误检测
    """
    return crc8(data, poly=0xA7, init=0x00, ref_in=True, ref_out=True, xor_out=0x00)


def crc8_j1850(data: bytes) -> int:
    """
    CRC-8/SAE-J1850
    poly=0x1D init=0xFF refin=false refout=false xorout=0xFF
    汽车总线标准
    """
    return crc8(data, poly=0x1D, init=0xFF, ref_in=False, ref_out=False, xor_out=0xFF)


# ============= 验证测试 =============

def test_crc8_implementations():
    """使用已知测试向量验证CRC实现"""

    test_data = b"123456789"

    # CRC-8/MAXIM - 期望值来自Maxim官方文档
    assert crc8_maxim(test_data) == 0xA1, f"CRC-8/MAXIM 测试失败"
    print(f"✓ CRC-8/MAXIM: 0x{crc8_maxim(test_data):02X}")

    # CRC-8/AUTOSAR - 期望值来自AUTOSAR规范
    assert crc8_autosar(test_data) == 0xDF, f"CRC-8/AUTOSAR 测试失败"
    print(f"✓ CRC-8/AUTOSAR: 0x{crc8_autosar(test_data):02X}")

    # CRC-8/LTE - 期望值来自3GPP规范
    assert crc8_lte(test_data) == 0xEA, f"CRC-8/LTE 测试失败"
    print(f"✓ CRC-8/LTE: 0x{crc8_lte(test_data):02X}")

    # CRC-8/SMBUS - 期望值来自SMBus规范
    assert crc8_smbus(test_data) == 0xF4, f"CRC-8/SMBUS 测试失败"
    print(f"✓ CRC-8/SMBUS: 0x{crc8_smbus(test_data):02X}")

    # CRC-8/BLUETOOTH - 期望值来自蓝牙规范
    assert crc8_bluetooth(test_data) == 0x26, f"CRC-8/BLUETOOTH 测试失败"
    print(f"✓ CRC-8/BLUETOOTH: 0x{crc8_bluetooth(test_data):02X}")

    # CRC-8/SAE-J1850 - 期望值来自SAE J1850规范
    assert crc8_j1850(test_data) == 0x4B, f"CRC-8/SAE-J1850 测试失败"
    print(f"✓ CRC-8/SAE-J1850: 0x{crc8_j1850(test_data):02X}")

    print("\n所有CRC8实现通过验证！✓")


def crc8_manual_calculation(data: bytes, poly: int, init: int,
                            ref_in: bool, ref_out: bool, xor_out: int) -> int:
    """
    纯位操作实现（无查找表），用于交叉验证

    参考算法来源: https://reveng.sourceforge.io/crc-catalogue/
    """
    crc = init

    for byte in data:
        if ref_in:
            byte = reverse_bits(byte)

        crc ^= byte

        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFF

    if ref_out:
        crc = reverse_bits(crc)

    return crc ^ xor_out


# ============= 使用示例 =============

if __name__ == "__main__":
    # 运行验证测试
    print("=== CRC8 实现验证 ===")
    test_crc8_implementations()

    # 自定义数据测试
    print("\n=== 自定义数据测试 ===")
    test_bytes = b"Hello CRC8"

    print(f"输入数据: {test_bytes}")
    print(f"CRC-8/MAXIM: 0x{crc8_maxim(test_bytes):02X}")
    print(f"CRC-8/AUTOSAR: 0x{crc8_autosar(test_bytes):02X}")
    print(f"CRC-8/LTE: 0x{crc8_lte(test_bytes):02X}")

    # 演示如何创建自定义CRC8变体
    print("\n=== 自定义DVB-S2 CRC ===")
    # ITU-T G.704标准示例
    custom_crc = crc8(test_bytes, poly=0xD5, init=0x00,
                      ref_in=False, ref_out=False, xor_out=0x00)
    print(f"CRC-8/DVB-S2: 0x{custom_crc:02X}")
