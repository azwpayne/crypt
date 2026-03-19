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
    for _j in range(8):
      c = c << 1 ^ _poly if c & 2147483648 else c << 1
    custom_crc32_table.append(c & 0xFFFFFFFF)
  return custom_crc32_table


origin_crc32_table = generate_crc32_table(0x04C11DB7)


def get_crc32(bytes_arr):
  length = len(bytes_arr)
  if bytes_arr is not None:
    crc = 0xFFFFFFFF
    for i in range(length):
      crc = (crc << 8) ^ origin_crc32_table[
        (get_reverse(bytes_arr[i], 8) ^ (crc >> 24)) & 0xFF
      ]
  else:
    crc = 0xFFFFFFFF
  return get_reverse(crc ^ 0xFFFFFFFF, 32)


def get_reverse(temp_data, byte_length):
  reverse_data = 0
  for i in range(byte_length):
    reverse_data += ((temp_data >> i) & 1) << (byte_length - 1 - i)
  return reverse_data


data = b"azwpayne"

crc32 = get_crc32(data)
print("CRC32:", format(crc32, "0x"))
