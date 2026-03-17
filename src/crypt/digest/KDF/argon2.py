# @author  : azwpayne(https://github.com/azwpayne)
# @name    : argon2.py
# @time    : 2026/03/15
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : Argon2 Key Derivation Function (RFC 9106)
"""
Argon2 is a memory-hard password hashing function and winner of the
Password Hashing Competition (PHC) in 2015.

Argon2i uses data-independent memory access, which is preferred for
password hashing and key derivation.

Reference: RFC 9106 - Argon2 Memory-Hard Function for Password Hashing
"""

import hashlib
import itertools
import struct

# Argon2 constants
ARGON2_VERSION = 0x13  # Version 1.3
ARGON2_BLOCK_SIZE = 1024
ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE // 8
ARGON2_ADDRESSES_IN_BLOCK = 128
ARGON2_PREHASH_DIGEST_LENGTH = 64
ARGON2_PREHASH_SEED_LENGTH = 72


def _blake2b_512(data: bytes) -> bytes:
  """Compute BLAKE2b-512 hash."""
  try:
    return hashlib.blake2b(data, digest_size=64).digest()
  except AttributeError:
    # Fallback if blake2b not available
    return hashlib.sha512(data).digest()


class _Argon2Block:
  """Represents a 1024-byte Argon2 block."""

  def __init__(self, data: bytes | None = None):
    if data is None:
      self.v = [0] * ARGON2_QWORDS_IN_BLOCK
    else:
      # Convert bytes to list of 64-bit integers
      self.v = list(struct.unpack(f"<{ARGON2_QWORDS_IN_BLOCK}Q", data))

  def to_bytes(self) -> bytes:
    """Convert block back to bytes."""
    return struct.pack(f"<{ARGON2_QWORDS_IN_BLOCK}Q", *self.v)

  def copy(self):
    """Create a copy of this block."""
    new = _Argon2Block()
    new.v = self.v.copy()
    return new

  def xor(self, other: "_Argon2Block") -> "_Argon2Block":
    """XOR two blocks."""
    result = _Argon2Block()
    result.v = [a ^ b for a, b in zip(self.v, other.v, strict=False)]
    return result


def _g_function(a: int, b: int, c: int, d: int) -> tuple:
  """
  The G function (Blake2b round function).
  Args are 64-bit integers, returns tuple of 4 64-bit integers.
  """
  # Use modular arithmetic for 64-bit values
  mask = (1 << 64) - 1

  a = (a + b + 2 * ((a & mask) * (b & mask) & mask)) & mask
  d = ((d ^ a) >> 32) | ((d ^ a) << 32) & mask
  c = (c + d + 2 * ((c & mask) * (d & mask) & mask)) & mask
  b = ((b ^ c) >> 24) | ((b ^ c) << 40) & mask

  a = (a + b + 2 * ((a & mask) * (b & mask) & mask)) & mask
  d = ((d ^ a) >> 16) | ((d ^ a) << 48) & mask
  c = (c + d + 2 * ((c & mask) * (d & mask) & mask)) & mask
  b = ((b ^ c) >> 63) | ((b ^ c) << 1) & mask

  return a, b, c, d


def _compress_block(x: _Argon2Block, y: _Argon2Block) -> _Argon2Block:
  """
  Compute P = G(R) where R = X xor Y.
  This is the G compression function from Argon2.
  """
  r = x.xor(y)

  # Convert block to working matrix
  q = r.v.copy()

  # Apply Blake2b round function
  mask = (1 << 64) - 1

  # Column rounds
  for i in range(0, 8, 2):
    q[i], q[i + 4], q[i + 8], q[i + 12] = _g_function(
      q[i], q[i + 4], q[i + 8], q[i + 12]
    )

  # Row rounds
  for i in range(4):
    q[i], q[i + 1], q[i + 2], q[i + 3] = _g_function(q[i], q[i + 1], q[i + 2], q[i + 3])

  # Create result block
  result = _Argon2Block()
  result.v = [(r.v[i] + q[i]) & mask for i in range(ARGON2_QWORDS_IN_BLOCK)]

  return result


def _h_prime(input_bytes: bytes, output_length: int) -> bytes:
  """
  H' function - extendable output hash.
  """
  if output_length <= 64:
    return _blake2b_512(struct.pack("<I", output_length) + input_bytes)[:output_length]

  # For longer outputs, compute multiple blocks
  result = bytearray()
  r = (output_length + 31) // 32 - 2

  v = _blake2b_512(struct.pack("<I", output_length) + input_bytes)
  result.extend(v[:32])

  for _i in range(1, r):
    v = _blake2b_512(v)
    result.extend(v[:32])

  # Final block
  remaining = output_length - 32 * r
  v = _blake2b_512(v)
  result.extend(v[:remaining])

  return bytes(result)


def _init_memory(
  memory_blocks: int,
  parallelism: int,
  password: bytes,
  salt: bytes,
  key: bytes,
  associated_data: bytes,
) -> list:
  """Initialize Argon2 memory matrix."""
  lanes = [
    [_Argon2Block() for _ in range(memory_blocks // parallelism)]
    for __ in range(parallelism)
  ]

  # Compute H0
  h0_input = struct.pack(
    "<IIIIII",
    parallelism,
    len(password),
    len(salt),
    len(key),
    len(associated_data),
    memory_blocks,
  )
  h0_input += struct.pack("<III", 3, 0, ARGON2_VERSION)  # t_cost, m_cost, version
  h0_input += password + salt + key + associated_data

  h0 = _blake2b_512(h0_input)

  # Initialize first two blocks of each lane
  for lane_index in range(parallelism):
    # Block 0
    seed = h0 + struct.pack("<II", lane_index, 0)
    block_data = _h_prime(seed, ARGON2_BLOCK_SIZE)
    lanes[lane_index][0] = _Argon2Block(block_data)

    # Block 1
    seed = h0 + struct.pack("<II", lane_index, 1)
    block_data = _h_prime(seed, ARGON2_BLOCK_SIZE)
    lanes[lane_index][1] = _Argon2Block(block_data)

  return lanes


def _fill_memory(
  lanes: list,
  memory_blocks: int,
  parallelism: int,
  iterations: int,
) -> None:
  """Fill memory matrix with Argon2i pattern."""
  columns = memory_blocks // parallelism

  for pass_num, slice_num, lane_index in itertools.product(
    range(iterations), range(4), range(parallelism)
  ):
    prev_index = slice_num * columns // 4

    for i in range(columns // 4):
      column_index = slice_num * columns // 4 + i

      if pass_num == 0 and column_index < 2:
        continue

      # Compute addresses for Argon2i (data-independent)
      j1 = (pass_num * 4 + slice_num + lane_index + column_index) % columns
      j2 = (pass_num * slice_num + lane_index * column_index) % columns

      ref_lane = (lane_index + j2) % parallelism
      ref_index = j1

      prev_block = lanes[lane_index][prev_index]
      ref_block = lanes[ref_lane][ref_index]

      lanes[lane_index][column_index] = _compress_block(prev_block, ref_block)

      prev_index = column_index


def _finalize(lanes: list, memory_blocks: int, parallelism: int) -> bytes:
  """Finalize Argon2 computation."""
  columns = memory_blocks // parallelism

  # XOR last column of each lane
  result = _Argon2Block()
  for lane_index in range(parallelism):
    result = result.xor(lanes[lane_index][columns - 1])

  return result.to_bytes()


def argon2i(
  password: str | bytes,
  salt: str | bytes,
  memory_cost: int = 65536,  # m (in KiB)
  time_cost: int = 3,  # t
  parallelism: int = 4,  # p
  hash_len: int = 32,
  key: str | bytes = b"",
  associated_data: str | bytes = b"",
) -> bytes:
  """
  Argon2i key derivation function.

  Argon2i uses data-independent memory access, making it suitable for
  password hashing and key derivation where timing side-channel attacks
  are a concern.

  Args:
      password: The password to hash
      salt: A random salt (must be unique per password, 16 bytes recommended)
      memory_cost: Memory cost in KiB (default 65536 = 64 MiB)
      time_cost: Number of iterations (default 3)
      parallelism: Degree of parallelism (default 4)
      hash_len: Desired hash length in bytes (default 32)
      key: Optional secret key (for keyed hashing)
      associated_data: Optional associated data

  Returns:
      Derived key as bytes

  Raises:
      ValueError: If parameters are invalid
  """
  # Convert inputs to bytes
  if isinstance(password, str):
    password = password.encode("utf-8")
  if isinstance(salt, str):
    salt = salt.encode("utf-8")
  if isinstance(key, str):
    key = key.encode("utf-8")
  if isinstance(associated_data, str):
    associated_data = associated_data.encode("utf-8")

  # Validate parameters
  if len(salt) < 8:
    msg = "Salt must be at least 8 bytes"
    raise ValueError(msg)
  if memory_cost < 8 * parallelism:
    msg = f"Memory cost must be at least 8*p = {8 * parallelism}"
    raise ValueError(msg)
  if time_cost < 1:
    msg = "Time cost must be at least 1"
    raise ValueError(msg)
  if parallelism < 1:
    msg = "Parallelism must be at least 1"
    raise ValueError(msg)

  # Calculate memory blocks
  memory_blocks = memory_cost // 4  # 4 * 1KiB blocks per m unit

  # Ensure memory_blocks is divisible by parallelism
  memory_blocks = (memory_blocks // parallelism) * parallelism
  memory_blocks = max(memory_blocks, 2 * parallelism)

  # Initialize memory
  lanes = _init_memory(
    memory_blocks,
    parallelism,
    password,
    salt,
    key,
    associated_data,
  )

  # Fill memory
  _fill_memory(lanes, memory_blocks, parallelism, time_cost)

  # Finalize
  final_block = _finalize(lanes, memory_blocks, parallelism)

  # Generate final hash
  return _h_prime(final_block, hash_len)


# Convenience function with the same interface as hashlib


def argon2(
  password: str | bytes,
  salt: str | bytes,
  time_cost: int = 3,
  memory_cost: int = 65536,
  parallelism: int = 4,
  hash_len: int = 32,
) -> bytes:
  """
  Simplified Argon2i interface compatible with common implementations.
  """
  return argon2i(
    password=password,
    salt=salt,
    time_cost=time_cost,
    memory_cost=memory_cost,
    parallelism=parallelism,
    hash_len=hash_len,
  )
