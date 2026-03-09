# @time    : 2026/1/10 08:02
# @name    : base62.py
# @author  : azwpayne
# @desc    :
import string

# Base62 字符集：0-9, A-Z, a-z
BASE62_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
BASE = len(BASE62_ALPHABET)
ALPHABET_MAP = {char: index for index, char in enumerate(BASE62_ALPHABET)}


def encode(num: int) -> str:
    """
    将非负整数编码为 base62 字符串

    Args:
        num: 要编码的非负整数

    Returns:
        base62 编码字符串
    """
    if num == 0:
        return BASE62_ALPHABET[0]

    result = []
    while num > 0:
        num, remainder = divmod(num, BASE)
        result.append(BASE62_ALPHABET[remainder])

    return "".join(reversed(result))


def decode(base62_str: str) -> int:
    """
    将 base62 字符串解码为整数

    Args:
        base62_str: base62 编码字符串

    Returns:
        解码后的整数
    """
    # 移除可能的空格和换行符
    base62_str = base62_str.strip()

    if not base62_str:
        raise ValueError("空字符串无法解码")

    result = 0
    for char in base62_str:
        if char not in ALPHABET_MAP:
            raise ValueError(f"无效的 base62 字符: '{char}'")

        result = result * BASE + ALPHABET_MAP[char]

    return result


def is_valid_base62(base62_str: str) -> bool:
    """
    检查字符串是否为有效的 base62 编码

    Args:
        base62_str: 要检查的字符串

    Returns:
        如果是有效的 base62 字符串则返回 True
    """
    if not base62_str:
        return False

    for char in base62_str:
        if char not in ALPHABET_MAP:
            return False

    return True


# 示例使用
if __name__ == "__main__":
    # 测试一些数字
    test_numbers = [0, 1, 10, 100, 1000, 123456789, 9876543210]

    for num in test_numbers:
        encoded = encode(num)
        decoded = decode(encoded)
        print(
            f"数字: {num:12d} -> 编码: {encoded:8s} -> 解码: {decoded:12d} {'✓' if num == decoded else '✗'}")

    # 测试边界情况
    print("\n特殊测试:")

    # 最大单字符
    print(f"最大单字符 '{BASE62_ALPHABET[-1]}' 解码为: {decode(BASE62_ALPHABET[-1])}")

    # 测试无效输入
    test_invalid = ["@#$", "abc-123", "ABC 123"]
    for invalid in test_invalid:
        try:
            decode(invalid)
            print(f"'{invalid}' 不应该成功解码")
        except ValueError as e:
            print(f"'{invalid}' 正确触发错误: {e}")

    # 有效性检查
    test_strings = ["abc123", "ABC123", "123456", "abc@123"]
    for s in test_strings:
        print(f"'{s}' 是有效的base62吗? {is_valid_base62(s)}")

    # 大数测试
    large_num = 10 ** 18
    encoded = encode(large_num)
    decoded = decode(encoded)
    print(
        f"\n大数测试: {large_num} -> 编码: {encoded} -> 解码: {decoded} {'✓' if large_num == decoded else '✗'}")
