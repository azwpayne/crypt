# @author  : azwpayne(https://github.com/azwpayne)
# @name    : utils.py
# @time    : 2026/3/11 01:37 Wed
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :

import math
import struct

# Keccak-f[1600] parameters
KECCAK_F_WIDTH = 1600  # State width in bits
KECCAK_F_ROUNDS = 24  # Number of permutation rounds

# Round constants for Keccak-f[1600]
KECCAK_RC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]

# Rotation offsets for rho step
KECCAK_ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def rotate_left_64(x: int, n: int) -> int:
    """Perform left circular rotation on a 64-bit integer.

    Args:
        x: The 64-bit integer to rotate
        n: Number of bits to rotate left

    Returns:
        The rotated 64-bit integer
    """
    n = n % 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def bytes_to_lanes(data: bytes) -> list[int]:
    """Convert bytes to 25 64-bit lanes (little-endian).

    Args:
        data: Input bytes (up to 200 bytes)

    Returns:
        List of 25 64-bit integers
    """
    lanes = [0] * 25
    for i in range(min(len(data) // 8, 25)):
        lanes[i] = struct.unpack("<Q", data[i * 8 : (i + 1) * 8])[0]
    return lanes


def lanes_to_bytes(lanes: list[int]) -> bytes:
    """Convert 25 64-bit lanes to bytes (little-endian).

    Args:
        lanes: List of 25 64-bit integers

    Returns:
        Bytes representation (200 bytes)
    """
    result = bytearray()
    for lane in lanes:
        result.extend(struct.pack("<Q", lane))
    return bytes(result)


def keccak_f_1600(state: list[int]) -> list[int]:
    """Keccak-f[1600] permutation function.

    Applies 24 rounds of the Keccak permutation.

    Args:
        state: List of 25 64-bit integers representing the state

    Returns:
        Permuted state as list of 25 64-bit integers
    """
    # Convert to 5x5 matrix
    A = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            A[x][y] = state[x + 5 * y]

    # 24 rounds
    for round_num in range(KECCAK_F_ROUNDS):
        # Theta step
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rotate_left_64(C[(x + 1) % 5], 1) for x in range(5)]

        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]

        # Rho and Pi steps
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rotate_left_64(A[x][y], KECCAK_ROTATION_OFFSETS[x][y])

        # Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

        # Iota step
        A[0][0] ^= KECCAK_RC[round_num]

    # Convert back to list
    result = [0] * 25
    for x in range(5):
        for y in range(5):
            result[x + 5 * y] = A[x][y]

    return result


def sieve_of_eratosthenes(sieve_upper_bound: int) -> list[int]:
  """
    生成 [2, limit] 内所有素数，时间复杂度 O(n log log n)

  素数（也称质数）是大于 1 的自然数，且只能被 1 和它自身整除。

  换句话说，如果一个数 n>1 ，且除了 1 和 n  之外没有其他正因数，那它就是素数。

  核心特征:
  - 因数个数：恰好有 2 个正因数（1 和它本身）
  - 最小素数：2（也是唯一的偶素数）
  - 前几个素数：2, 3, 5, 7, 11, 13, 17, 19, 23, 29...

  为什么 1 不是素数？
    历史上曾将 1 视为素数，但现代数学将其排除，主要原因：
    1. 算术基本定理：任何大于 1 的整数都可以唯一分解为素数的乘积。如果 1 是素数，6=2 * 3=1^2×2×3=1^2×3...  分解就不唯一了。
    2. 素数计数函数：π(n)  表示不超过 n  的素数个数，排除 1 使公式更优雅。
  :param sieve_upper_bound: 素数搜索的上限值（包含）, sieve_upper_bound必须大于2
  :return: 包含所有不超过 sieve_upper_bound 的素数的列表  生成 [2, limit] 内所有素数，时间复杂度 O(n log log n)

  素数（也称质数）是大于 1 的自然数，且只能被 1 和它自身整除。

  换句话说，如果一个数 n>1 ，且除了 1 和 n  之外没有其他正因数，那它就是素数。

  核心特征:
  - 因数个数：恰好有 2 个正因数（1 和它本身）
  - 最小素数：2（也是唯一的偶素数）
  - 前几个素数：2, 3, 5, 7, 11, 13, 17, 19, 23, 29...

  为什么 1 不是素数？
    历史上曾将 1 视为素数，但现代数学将其排除，主要原因：
    1. 算术基本定理：任何大于 1 的整数都可以唯一分解为素数的乘积。如果 1 是素数，6=2 * 3=1^2×2×3=1^2×3...  分解就不唯一了。
    2. 素数计数函数：π(n)  表示不超过 n  的素数个数，排除 1 使公式更优雅。
  Args:
    sieve_upper_bound: 素数搜索的上限值（包含）, sieve_upper_bound必须大于2

  Returns:
    包含所有不超过 sieve_upper_bound 的素数的列表

  """
  if sieve_upper_bound < 2:
    msg = "sieve_upper_bound 必须大于2"
    raise ValueError(msg)

  # 初始化全部标记为 True
  is_prime = [True] * (sieve_upper_bound + 1)
  is_prime[0] = is_prime[1] = False

  for x in range(2, int(sieve_upper_bound**0.5) + 1):
    if is_prime[x]:
      # 标记 i 的所有倍数
      # for j in range(i * i, limit + 1, i):
      #   is_prime[j] = False
      # 使用切片赋值优化：标记 i 的所有倍数
      is_prime[x * x : sieve_upper_bound + 1 : x] = [False] * len(
        is_prime[x * x : sieve_upper_bound + 1 : x]
      )

  # return [i for i, prime in enumerate(is_prime) if prime]
  from itertools import compress

  return list(compress(range(sieve_upper_bound + 1), is_prime))


def generate_n_sieve(n) -> list[int]:
  """生成前 n 个质数"""

  if n <= 0:
    return []

  # 使用质数定理估算第 n 个质数上界
  # 当 n >= 6 时，第 n 个质数 < n * (ln(n) + ln(ln(n)))
  limit = 15 if n < 6 else int(n * (math.log(n) + math.log(math.log(n)))) + 10

  # 使用埃拉托斯特尼筛法生成质数
  primes = sieve_of_eratosthenes(limit)

  # 如果质数不够，扩展筛选范围. 否则，使用扩展筛选范围
  while len(primes) < n:
    limit <<= 1  # limit *= 2
  primes = sieve_of_eratosthenes(limit)

  return primes[:n]
