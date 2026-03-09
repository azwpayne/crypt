# @time    : 2025/12/24 13:21
# @name    : crc32.py
# @author  : azwpayne
# @desc    :


key = 0xEDB88320  # 反式


def calculate_crc32(data):
    crc = 0xFFFFFFFF  # 初始值
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:  # 奇数
                crc = (crc >> 1) ^ key
            else:  # 偶数
                crc >>= 1
    return crc ^ 0xFFFFFFFF  # 取反


# 示例数据
data = b"azwpayne"

crc32 = calculate_crc32(data)
# 打印结果
print("CRC32:", format(crc32, "08x"))


# 正式
def generate_crc32_table(_poly):
    custom_crc32_table = []
    for i in range(256):
        c = i << 24
        for j in range(8):
            if c & 0x80000000:
                c = (c << 1) ^ _poly
            else:
                c = c << 1
        custom_crc32_table.append(c & 0xffffffff)
    return custom_crc32_table


origin_crc32_table = generate_crc32_table(0x04c11db7)


def getCrc32(bytes_arr):
    length = len(bytes_arr)
    if bytes_arr is not None:
        crc = 0xffffffff
        for i in range(length):
            crc = (crc << 8) ^ origin_crc32_table[
                (getReverse(bytes_arr[i], 8) ^ (crc >> 24)) & 0xff]
    else:
        crc = 0xffffffff
    crc = getReverse(crc ^ 0xffffffff, 32)
    return crc


def getReverse(tempData, byte_length):
    reverseData = 0
    for i in range(byte_length):
        reverseData += ((tempData >> i) & 1) << (byte_length - 1 - i)
    return reverseData


data = b"azwpayne"

crc32 = getCrc32(data)
print("CRC32:", format(crc32, "0x"))
