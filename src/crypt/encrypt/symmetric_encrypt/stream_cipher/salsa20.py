# @time    : 2025/12/24 13:32
# @name    : Salsa20.py
# @author  : azwpayne
# @desc    :


import struct


def rotl(v, n):
  """对32位无符号整数 v 进行循环左移 n 位。"""
  return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def quarter_round(x, a, b, c, d):
  """Salsa20 的四分轮函数，对状态数组 x 的 a, b, c, d 四个位置进行操作。"""
  x[b] ^= rotl((x[a] + x[d]) & 0xFFFFFFFF, 7)
  x[c] ^= rotl((x[b] + x[a]) & 0xFFFFFFFF, 9)
  x[d] ^= rotl((x[c] + x[b]) & 0xFFFFFFFF, 13)
  x[a] ^= rotl((x[d] + x[c]) & 0xFFFFFFFF, 18)


# def littleendian(b):
#     """将 4 字节的小端序数据转换为 32 位整数"""
#     return struct.unpack("<L", b)[0]


def salsa20_block(k, c, n):
  constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
  key_words = list(struct.unpack("<8I", k))
  nonce_words = list(struct.unpack("<2I", n))
  state = [0] * 16
  state[0] = constants[0]
  state[1] = key_words[0]
  state[2] = key_words[1]
  state[3] = key_words[2]
  state[4] = key_words[3]
  state[5] = constants[1]
  state[6] = nonce_words[0]
  state[7] = nonce_words[1]
  state[8] = c & 0xFFFFFFFF
  state[9] = (c >> 32) & 0xFFFFFFFF  # 几乎是0
  state[10] = constants[2]
  state[11] = key_words[4]
  state[12] = key_words[5]
  state[13] = key_words[6]
  state[14] = key_words[7]
  state[15] = constants[3]

  working_state = state.copy()

  # 进行 20 轮运算（10 次双轮，每次包括列轮和对角线轮）
  for _ in range(10):
    quarter_round(working_state, 0, 4, 8, 12)
    quarter_round(working_state, 5, 9, 13, 1)
    quarter_round(working_state, 10, 14, 2, 6)
    quarter_round(working_state, 15, 3, 7, 11)
    quarter_round(working_state, 0, 1, 2, 3)
    quarter_round(working_state, 5, 6, 7, 4)
    quarter_round(working_state, 10, 11, 8, 9)
    quarter_round(working_state, 15, 12, 13, 14)

  for i in range(16):
    working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

  return struct.pack("<16L", *working_state)


def salsa20_encrypt(k, n, c, p):
  ciphertext = bytearray()
  block_count = (len(p) + 63) // 64
  for i in range(block_count):
    keystream = salsa20_block(k, c + i, n)
    block = p[i * 64 : (i + 1) * 64]
    for j in range(len(block)):
      ciphertext.append(block[j] ^ keystream[j])
  return bytes(ciphertext)


if __name__ == "__main__":
  key = bytes.fromhex(
    "0ead0c2e54a978e8b303ed242e6d313f253ea446bcbfc6f86d9809c09d191e22"
  )
  nonce = bytes.fromhex("9565542946c322be")
  counter = 0
  plaintext = bytes.fromhex("0000000001000200cdb87f280000000001000200cdb87f28")
  print("明文:", plaintext.hex())

  test_ciphertext = salsa20_encrypt(key, nonce, counter, plaintext)
  print("密文 (hex):", test_ciphertext.hex())

  decrypted = salsa20_encrypt(key, nonce, counter, test_ciphertext)
  print("解密后明文:", decrypted.hex())
