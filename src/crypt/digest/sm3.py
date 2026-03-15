# @time    : 2025/12/24 13:29
# @name    : sm3.py
# @author  : azwpayne
# @desc    :


def left_rotate(value, shift_bits):
  """
  对32位整数进行左循环移位

  :param value: 要移位的32位整数
  :param shift_bits: 左移的位数
  :return: 循环移位后的32位整数
  """
  # 规范化移位位数到0-31范围内
  normalized_shift = shift_bits % 32
  # 如果移位位数为0，直接返回原值
  if normalized_shift == 0:
    return value & 0xFFFFFFFF
  # 执行左循环移位操作
  # 将value左移normalized_shift位，同时将右边被移出的位移到左边
  return ((value << normalized_shift) | (value >> (32 - normalized_shift))) & 0xFFFFFFFF


# 常量 Tj，定义为两个不同的值
T = [0x79CC4519 if j < 16 else 0x7A879D8A for j in range(64)]


# def left_rotate(x, n):
#     return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# 压缩函数 FFj 和 GGj 的定义
def FF(X, Y, Z, j):
  return X ^ Y ^ Z if j < 16 else (X & Y) | (X & Z) | (Y & Z)


def GG(X, Y, Z, j):
  return X ^ Y ^ Z if j < 16 else (X & Y) | (~X & Z)


# P0 和 P1 置换函数
def P0(X):
  return X ^ left_rotate(X, 9) ^ left_rotate(X, 17)


def P1(X):
  return X ^ left_rotate(X, 15) ^ left_rotate(X, 23)


# 填充消息，使得消息长度是 512 位的倍数
def padding(message):
  l = len(message) * 8
  message += b"\x80"
  while (len(message) + 8) % 64 != 0:
    message += b"\x00"
  message += l.to_bytes(8, "big")
  return message


# 消息扩展函数
def message_expand(block):
  W = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
  for j in range(16, 68):  # 52轮
    W.append(
      P1(W[j - 16] ^ W[j - 9] ^ left_rotate(W[j - 3], 15))
      ^ left_rotate(W[j - 13], 7)
      ^ W[j - 6]
    )
  W_ = [W[j] ^ W[j + 4] for j in range(64)]
  return W, W_


# 压缩函数 CF
def CF(V, block):
  A, B, C, D, E, F, G, H = V
  W, W_ = message_expand(block)

  for j in range(64):
    SS1 = left_rotate(
      (left_rotate(A, 12) + E + left_rotate(T[j], j % 32)) & 0xFFFFFFFF, 7
    )
    SS2 = SS1 ^ left_rotate(A, 12)

    TT1 = (FF(A, B, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF
    TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF

    D = C
    C = left_rotate(B, 9)
    B = A
    A = TT1
    H = G
    G = left_rotate(F, 19)
    F = E
    E = P0(TT2)

  return [(V[i] ^ X) & 0xFFFFFFFF for i, X in enumerate([A, B, C, D, E, F, G, H])]


# 主函数
def sm3(message):
  # 初始向量 IV
  IV = [
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
  ]

  m = padding(message)
  blocks = [m[i : i + 64] for i in range(0, len(m), 64)]

  V = IV
  for block in blocks:
    V = CF(V, block)

  res = "".join(f"{x:08x}" for x in V)
  print(res)


# 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b

msg = b""
sm3(msg)
