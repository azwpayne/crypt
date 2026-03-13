# @author  : azwpayne(https://github.com/azwpayne)
# @name    : sha_iv.py
# @time    : 2026/3/10 23:44 Tue
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    :
import math

from utils import generate_n_sieve

# SHA 算法初始哈希值生成的素数常量
# _SHA_INITIAL_HASH_PRIMES = generate_n_sieve(8)
_SHA_INITIAL_HASH_PRIMES = generate_n_sieve(16)

# 算法配置映射
_SUPPORTED_ALGORITHMS = {
  "SHA-256": {"bits": 32, "mask": 0xFFFFFFFF},
  "SHA-512": {"bits": 64, "mask": 0xFFFFFFFFFFFFFFFF},
}


def generate_sha2_initialization_vector(algorithm="SHA-256"):
  """
  生成 SHA-256 或 SHA-512 的初始哈希值 H[0..7]

  使用纯整数算法避免浮点数精度问题：
  frac(sqrt(p)) * 2^n = floor(sqrt(p * 2^(2n))) - floor(sqrt(p)) * 2^n

  Args:
      algorithm: 算法名称，仅支持 "SHA-256" 或 "SHA-512"

  Returns:
      包含 8 个整数的列表，表示初始哈希值 H[0..7]

  Raises:
      ValueError: 当 algorithm 参数不支持时

  # Examples:
      >>> generate_sha2_initialization_vector("SHA-256")
      [0x6a09e667, 0xbb67ae85, ...]

      >>> generate_sha2_initialization_vector("SHA-512")
      [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, ...]
  """
  # 验证算法参数
  if not isinstance(algorithm, str):
    msg = f"algorithm 参数必须是字符串, 当前类型为: {type(algorithm).__name__}"
    raise TypeError(msg)

  if algorithm not in _SUPPORTED_ALGORITHMS:
    msg = (
      f"不支持的算法: '{algorithm}'。仅支持: {', '.join(_SUPPORTED_ALGORITHMS.keys())}"
    )
    raise ValueError(msg)

  config = _SUPPORTED_ALGORITHMS[algorithm]
  bits, mask = config["bits"], config["mask"]

  # initial_hash_values = []
  # for p in _SHA_INITIAL_HASH_PRIMES:
  #   # 计算 floor(sqrt(p * 2^(2*bits)))
  #   sqrt_scaled = math.isqrt(p << (2 * bits))
  #
  #   # 计算 floor(sqrt(p)) * 2^bits
  #   int_part = math.isqrt(p) << bits
  #
  #   # 差值即为 floor(frac(sqrt(p)) * 2^bits)
  #   h = (sqrt_scaled - int_part) & mask
  #   initial_hash_values.append(h)
  #
  # return initial_hash_values
  return [
    (math.isqrt(p << (2 * bits)) - (math.isqrt(p) << bits)) & mask
    for p in _SHA_INITIAL_HASH_PRIMES
  ]


if __name__ == "__main__":
  # # 使用示例
  print("SHA-256 H[0..7]:")
  for i, h in enumerate(generate_sha2_initialization_vector("SHA-256")):
    print(f"  H[{i}] = {h:#x}")

  print("\nSHA-512 H[0..7]:")
  for i, h in enumerate(generate_sha2_initialization_vector("SHA-512")):
    print(f"  H[{i}] = {h:#x}")

# if __name__ == "__main__":
#   print(sieve_of_eratosthenes(40))
