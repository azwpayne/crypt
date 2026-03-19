# @author  : azwpayne(https://github.com/azwpayne)
# @name    : utils.py
# @time    : 2026/3/11 01:37 Wed
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :

import math
import struct

# Keccak-f[1600] parameters
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
  # Pad to 200 bytes and unpack all 25 lanes at once (more efficient than loop)
  return list(struct.unpack("<25Q", data.ljust(200, b"\x00")[:200]))


def lanes_to_bytes(lanes: list[int]) -> bytes:
  """Convert 25 64-bit lanes to bytes (little-endian).

  Args:
      lanes: List of 25 64-bit integers

  Returns:
      Bytes representation (200 bytes)
  """
  # Pack all 25 lanes at once (more efficient than loop with bytearray.extend)
  return struct.pack("<25Q", *lanes)


def keccak_f_1600(state: list[int]) -> list[int]:
  """Keccak-f[1600] permutation function.

  Applies 24 rounds of the Keccak permutation.

  Args:
      state: List of 25 64-bit integers representing the state

  Returns:
      Permuted state as list of 25 64-bit integers
  """
  # Convert to 5x5 matrix
  a = [[0] * 5 for _ in range(5)]
  for x in range(5):
    for y in range(5):
      a[x][y] = state[x + 5 * y]

  # Pre-allocate working matrices to avoid repeated allocations in the loop
  c = [0] * 5
  d = [0] * 5
  b = [[0] * 5 for _ in range(5)]

  # 24 rounds
  for round_num in range(KECCAK_F_ROUNDS):
    # Theta step
    for x in range(5):
      c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4]
    for x in range(5):
      d[x] = c[(x - 1) % 5] ^ rotate_left_64(c[(x + 1) % 5], 1)

    for x in range(5):
      for y in range(5):
        a[x][y] ^= d[x]

    # Rho and Pi steps
    for x in range(5):
      for y in range(5):
        b[y][(2 * x + 3 * y) % 5] = rotate_left_64(
          a[x][y], KECCAK_ROTATION_OFFSETS[x][y]
        )

    # Chi step
    for x in range(5):
      for y in range(5):
        a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

    # Iota step
    a[0][0] ^= KECCAK_RC[round_num]

  # Convert back to list (column-major order: x + 5*y)
  return [a[x][y] for y in range(5) for x in range(5)]


def sieve_of_eratosthenes(sieve_upper_bound: int) -> list[int]:
  """Generate all primes in [2, sieve_upper_bound] using Sieve of Eratosthenes.

  Time complexity: O(n log log n)

  A prime number is a natural number greater than 1 that has no positive divisors
  other than 1 and itself.

  Core characteristics:
  - Exactly 2 positive divisors (1 and itself)
  - Smallest prime: 2 (also the only even prime)
  - First few primes: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29...

  Why 1 is not prime:
    Historically 1 was considered prime, but modern mathematics excludes it because:
    1. Fundamental Theorem of Arithmetic: Every integer > 1 can be uniquely factored
       into primes. If 1 were prime, 6 = 2×3 = 1²×2×3 = ... would have infinite factorizations.
    2. Prime counting function π(n) is more elegant when 1 is excluded.

  Args:
    sieve_upper_bound: Upper bound for prime search (inclusive). Must be >= 2.

  Returns:
    List of all primes <= sieve_upper_bound

  Raises:
    ValueError: If sieve_upper_bound < 2
  """
  if sieve_upper_bound < 2:
    msg = "sieve_upper_bound must be >= 2"
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
