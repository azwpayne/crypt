# @author  : azwpayne(https://github.com/azwpayne)
# @name    : test_crc.py
# @time    : 2026/3/9 20:56 Mon
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :
import unittest
from crypt.digest.CRC import crc8


class TestCRC(unittest.TestCase):
  """test crc algorithms"""

  def test_crc8_implementations(self):
    """使用已知测试向量验证CRC实现"""

    test_data = b"123456789"

    # CRC-8/MAXIM - 期望值来自Maxim官方文档
    assert crc8.crc8_maxim(test_data) == 0xA1, "CRC-8/MAXIM 测试失败"
    print(f"✓ CRC-8/MAXIM: 0x{crc8.crc8_maxim(test_data):02X}")

    # CRC-8/AUTOSAR - 期望值来自AUTOSAR规范
    assert crc8.crc8_autosar(test_data) == 0xDF, "CRC-8/AUTOSAR 测试失败"  # noqa: PLR2004, S101
    print(f"✓ CRC-8/AUTOSAR: 0x{crc8.crc8_autosar(test_data):02X}")

    # CRC-8/LTE - 期望值来自3GPP规范
    assert crc8.crc8_lte(test_data) == 0xEA, "CRC-8/LTE 测试失败"  # noqa: PLR2004, S101
    print(f"✓ CRC-8/LTE: 0x{crc8.crc8_lte(test_data):02X}")

    # CRC-8/SMBUS - 期望值来自SMBus规范
    assert crc8.crc8_smbus(test_data) == 0xF4, "CRC-8/SMBUS 测试失败"  # noqa: PLR2004, S101
    print(f"✓ CRC-8/SMBUS: 0x{crc8.crc8_smbus(test_data):02X}")

    # CRC-8/BLUETOOTH - 期望值来自蓝牙规范
    assert crc8.crc8_bluetooth(test_data) == 0x26, "CRC-8/BLUETOOTH 测试失败"  # noqa: PLR2004, S101
    print(f"✓ CRC-8/BLUETOOTH: 0x{crc8.crc8_bluetooth(test_data):02X}")

    # CRC-8/SAE-J1850 - 期望值来自SAE J1850规范
    assert crc8.crc8_j1850(test_data) == 0x4B, "CRC-8/SAE-J1850 测试失败"  # noqa: PLR2004, S101
    print(f"✓ CRC-8/SAE-J1850: 0x{crc8.crc8_j1850(test_data):02X}")

    print("\n所有CRC8实现通过验证! ✓")

  def test_crc8(self):
    pass

  def test_crc12(self):
    pass

  def test_crc16(self):
    pass

  def test_crc16_ccitt(self):
    pass

  def test_crc32(self):
    pass
