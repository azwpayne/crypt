# @time    : 2026/1/10 07:30
# @name    : hex2bin.py
# @author  : azwpayne
# @desc    :


def hex_to_bin(hex_str: str, min_bits: int = 0) -> str:
    """
    基础转换：十六进制字符串 → 二进制字符串

    参数:
        hex_str: 十六进制字符串(可含0x前缀或空格)
        min_bits: 最小输出位数，不足时左侧补零

    返回:
        二进制字符串，不含前缀和空格

    示例:
        >>> hex_to_bin("1A3F")
        '1101000111111'
        >>> hex_to_bin("0xFF", 8)
        '11111111'
        >>> hex_to_bin("12 34")
        '1001000110100'
    """
    # 清理输入：移除前缀、空格和换行符
    clean_hex = hex_str.replace("0x", "").replace(" ", "").replace("\n", "").strip()

    if not clean_hex:
        raise ValueError("输入不能为空")

    # 验证十六进制有效性
    try:
        int(clean_hex, 16)
    except ValueError:
        raise ValueError(f"无效的十六进制字符串: {hex_str}")

    # 转换并去掉 '0b' 前缀
    binary = bin(int(clean_hex, 16))[2:]

    # 按最小位数补零
    if min_bits > len(binary):
        binary = binary.zfill(min_bits)

    return binary


def hex_to_bin_grouped(hex_str: str, bits_per_group: int = 8) -> str:
    """
    分组格式化输出：每N位用空格分隔

    参数:
        hex_str: 十六进制字符串
        bits_per_group: 每组位数(默认8位=1字节)

    返回:
        格式化二进制字符串

    示例:
        >>> hex_to_bin_grouped("4D61726B", 8)
        '01001101 01100001 01110010 01101011'
    """
    binary = hex_to_bin(hex_str)

    # 确保总长度是分组位数的倍数
    remainder = len(binary) % bits_per_group
    if remainder != 0:
        binary = binary.zfill(len(binary) + (bits_per_group - remainder))

    # 分组并连接
    groups = [binary[j:j + bits_per_group]
              for j in range(0, len(binary), bits_per_group)]

    return " ".join(groups)


def hex_to_bin_array(hex_str: str) -> list[int]:
    """
    转换为位数组(整数列表)

    返回:
        [0, 1, 1, 0, ...] 形式的列表

    示例:
        >>> hex_to_bin_array("3F")
        [0, 0, 1, 1, 1, 1]
    """
    binary_str = hex_to_bin(hex_str)
    return [int(b) for b in binary_str]


def is_valid_hex(hex_str: str) -> bool:
    """
    验证字符串是否为有效十六进制格式

    示例:
        >>> is_valid_hex("1a2B3c")
        True
        >>> is_valid_hex("0xZZ")
        False
    """
    try:
        hex_str = hex_str.replace("0x", "").replace(" ", "").strip()
        int(hex_str, 16)
        return True
    except (ValueError, TypeError):
        return False


def hex_byte_to_bin(hex_byte: str, with_prefix: bool = False) -> str:
    """
    单字节转换：确保输出8位二进制

    参数:
        hex_byte: 1-2字符的十六进制(如 "A", "FF")
        with_prefix: 是否添加 '0b' 前缀

    示例:
        >>> hex_byte_to_bin("F")
        '00001111'
        >>> hex_byte_to_bin("F", with_prefix=True)
        '0b00001111'
    """
    clean = hex_byte.strip()
    if not (1 <= len(clean) <= 2):
        raise ValueError("单字节输入长度必须为1或2")

    binary = hex_to_bin(clean, min_bits=8)

    if with_prefix:
        return f"0b{binary}"
    return binary


# 批量转换辅助函数
def batch_hex_to_bin(hex_list: list[str]) -> list[str]:
    """
    批量转换十六进制列表

    示例:
        >>> batch_hex_to_bin(["1", "A", "FF"])
        ['1', '1010', '11111111']
    """
    return [hex_to_bin(h) for h in hex_list if is_valid_hex(h)]


#################

def bin_to_hex(bin_str: str, min_digits: int = 0) -> str:
    """
    基础转换：二进制字符串 → 十六进制字符串

    参数:
        bin_str: 二进制字符串(可含0b前缀或空格)
        min_digits: 最小输出位数，不足时左侧补零

    返回:
        十六进制字符串，不含前缀和空格(大写)

    示例:
        >>> bin_to_hex("1101000111111")
        '1A3F'
        >>> bin_to_hex("0b1111", 2)
        '0F'
        >>> bin_to_hex("1101 0010")
        'D2'
    """
    # 清理输入：移除前缀、空格和换行符
    clean_bin = bin_str.replace("0b", "").replace(" ", "").replace("\n", "").strip()

    if not clean_bin:
        raise ValueError("输入不能为空")

    # 验证二进制有效性
    if not all(c in "01" for c in clean_bin):
        raise ValueError(f"无效的二进制字符串: {bin_str}")

    # 如果长度不是4的倍数，左侧补零
    remainder = len(clean_bin) % 4
    if remainder != 0:
        clean_bin = "0" * (4 - remainder) + clean_bin

    # 转换并去掉 '0x' 前缀，转为大写
    hex_str = hex(int(clean_bin, 2))[2:].upper()

    # 按最小位数补零
    if min_digits > len(hex_str):
        hex_str = hex_str.zfill(min_digits)

    return hex_str


def bin_to_hex_grouped(bin_str: str, bytes_per_group: int = 1, separator: str = " ") -> str:
    """
    分组格式化输出：每N个字节用分隔符连接

    参数:
        bin_str: 二进制字符串
        bytes_per_group: 每组字节数(默认1)
        separator: 分隔符(默认空格)

    示例:
        >>> bin_to_hex_grouped("01001101011000010111001001101011", 1)
        '4D 61 72 6B'
        >>> bin_to_hex_grouped("1101011010111001", 2, ":")
        'DB:59'
    """
    hex_str = bin_to_hex(bin_str)

    # 确保总长度是分组长度的倍数(每组=bytes_per_group*2个十六进制字符)
    group_len = bytes_per_group * 2
    remainder = len(hex_str) % group_len
    if remainder != 0:
        hex_str = hex_str.zfill(len(hex_str) + (group_len - remainder))

    # 分组并连接
    groups = [hex_str[j:j + group_len]
              for j in range(0, len(hex_str), group_len)]

    return separator.join(groups)


def bin_byte_to_hex(bin_byte: str) -> str:
    """
    单字节转换：确保8位二进制转2位十六进制

    参数:
        bin_byte: 8位或更少位的二进制字符串

    示例:
        >>> bin_byte_to_hex("1111")
        '0F'
        >>> bin_byte_to_hex("11010010")
        'D2'
    """
    clean = bin_byte.strip()
    if len(clean) > 8:
        raise ValueError("单字节输入不能超过8位")

    return bin_to_hex(clean, min_digits=2)


def bin_to_hex_with_prefix(bin_str: str, prefix: str = "0x", min_digits: int = 0) -> str:
    """
    带前缀的转换输出

    示例:
        >>> bin_to_hex_with_prefix("11111111")
        '0xFF'
    """
    return f"{prefix}{bin_to_hex(bin_str, min_digits)}"


def is_valid_bin(bin_str: str) -> bool:
    """
    验证字符串是否为有效二进制格式

    示例:
        >>> is_valid_bin("101010")
        True
        >>> is_valid_bin("0b10201")
        False
    """
    try:
        clean_bin = bin_str.replace("0b", "").replace(" ", "").strip()
        if not clean_bin:
            return False
        return all(c in "01" for c in clean_bin)
    except (ValueError, TypeError):
        return False


def bin_bits_to_hex(bit_list: list[int]) -> str:
    """
    位列表转十六进制(0/1整数列表)

    参数:
        bit_list: [0, 1, 1, 0, ...] 形式的列表

    示例:
        >>> bin_bits_to_hex([0, 0, 1, 1, 1, 1])
        '3F'
    """
    if not all(b in (0, 1) for b in bit_list):
        raise ValueError("列表只能包含0或1")

    bin_str = "".join(str(b) for b in bit_list)
    return bin_to_hex(bin_str)


def byte_array_to_hex(byte_list: list[int]) -> str:
    """
    字节数组(0-255整数列表)转十六进制字符串

    示例:
        >>> byte_array_to_hex([77, 97, 114, 107])
        '4D61726B'
    """
    if not all(0 <= b <= 255 for b in byte_list):
        raise ValueError("字节值必须在0-255范围内")

    return "".join(f"{b:02X}" for b in byte_list)


# 批量转换辅助函数
def batch_bin_to_hex(bin_list: list[str]) -> list[str]:
    """
    批量转换二进制字符串列表

    示例:
        >>> batch_bin_to_hex(["1", "1010", "11111111"])
        ['1', 'A', 'FF']
    """
    return [bin_to_hex(b) for b in bin_list if is_valid_bin(b)]


# 使用示例和测试
if __name__ == "__main__":

    print("\n=============== hex2bin =================\n")
    # 基础转换
    print(f"1A3F → {hex_to_bin('1A3F')}")
    print(f"0xFF → {hex_to_bin('0xFF', 8)}")

    # 分组显示
    mac = "00:1A:2B"
    print(f"MAC地址: {hex_to_bin_grouped(mac.replace(':', ''), 8)}")

    # 位数组
    bits = hex_to_bin_array("3F")
    print(f"3F的位数组: {bits}")

    # 单字节
    print(f"字节A: {hex_byte_to_bin('A')}")

    # 验证
    print(f"是否有效: {is_valid_hex('0xAB12')}")

    # 批量转换
    hexes = ["1", "10", "FF", "1a2b"]
    print(f"批量: {batch_hex_to_bin(hexes)}")

    # 实际应用场景：解析寄存器标志位
    reg_value = "0x5A"
    binary_flags = hex_to_bin(reg_value, 8)
    print(f"\n寄存器值 {reg_value} 的二进制标志位:")
    for i, bit in enumerate(binary_flags):
        print(f"  Bit {7 - i}: {bit}")

    ############ bin2hex =================
    print("\n=============== bin2hex =================\n")
    # 基础转换
    print(f"1101000111111 → {bin_to_hex('1101000111111')}")
    print(f"0b1111 → {bin_to_hex('0b1111', 2)}")

    # 分组显示MAC地址
    mac_bin = "00000000000110100010101100111100"
    print(f"MAC二进制分组: {bin_to_hex_grouped(mac_bin, 1, ':')}")

    # 位列表转换
    bits = [0, 0, 1, 1, 1, 1]
    print(f"位列表[0,0,1,1,1,1] → {bin_bits_to_hex(bits)}")

    # 字节数组
    bytes_arr = [77, 97, 114, 107]
    print(f"字节数组{bytes_arr} → {byte_array_to_hex(bytes_arr)}")

    # 带前缀
    print(f'带前缀: {bin_to_hex_with_prefix("11111111")}')

    # 验证
    print(f"是否有效: {is_valid_bin('0b101010')}")

    # 批量转换
    bins = ["1", "1010", "11111111", "1001"]
    print(f"批量转换: {batch_bin_to_hex(bins)}")

    # 实际场景：解析IP地址
    ip_bin = "11000000101010000000000100000001"
    print(f"\nIP二进制 {ip_bin[:8]} {ip_bin[8:16]} {ip_bin[16:24]} {ip_bin[24:]}")
    ip_hex = bin_to_hex_grouped(ip_bin, 1, ".")
    print(f"十六进制IP: {ip_hex}")
    # 转换为十进制
    ip_dec = [str(int(h, 16)) for h in ip_hex.split(".")]
    print(f"点分十进制: {'.'.join(ip_dec)}")
