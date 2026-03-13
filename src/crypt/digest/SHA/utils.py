# @author  : azwpayne(https://github.com/azwpayne)
# @name    : utils.py
# @time    : 2026/3/11 01:37 Wed
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :

import math


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
