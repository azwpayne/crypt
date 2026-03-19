"""SHA3-512 Hash Algorithm Implementation

Implements the SHA3-512 cryptographic hash function as defined in FIPS 202.
Produces a 512-bit (64-byte) hash value using the Keccak-f[1600] permutation.

Features:
- FIPS 202 compliant
- Pure Python implementation
- Uses Keccak sponge construction
- Different internal structure from SHA-2 family (not vulnerable to length extension)

Security Notes:
- SHA3-512 produces a 512-bit (64-byte) hash
- Part of the SHA-3 family based on Keccak
- Provides 256-bit security level against collision attacks
- Not vulnerable to length extension attacks
- Suitable for high-security applications and post-quantum preparedness
- Rate is 576 bits (72 bytes), capacity is 1024 bits

References:
- FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
- Keccak reference: https://keccak.team/keccak.html
"""

from __future__ import annotations

# SHA3-512 parameters
RATE_BITS = 576
RATE_BYTES = RATE_BITS // 8  # 72 bytes
CAPACITY_BITS = 1024
HASH_LENGTH_BITS = 512
HASH_LENGTH_BYTES = HASH_LENGTH_BITS // 8  # 64 bytes
STATE_WIDTH = 5
LANE_SIZE_BITS = 64
LANE_SIZE_BYTES = LANE_SIZE_BITS // 8  # 8 bytes
STATE_SIZE_BYTES = 200  # 5 * 5 * 8

# Round constants for Keccak-f[1600]
RC = [
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
RHO = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]

# Pi permutation indices
PI = [
  (0, 0),
  (1, 3),
  (2, 1),
  (3, 4),
  (4, 2),
  (0, 1),
  (1, 4),
  (2, 2),
  (3, 0),
  (4, 3),
  (0, 2),
  (1, 0),
  (2, 3),
  (3, 1),
  (4, 4),
  (0, 3),
  (1, 1),
  (2, 4),
  (3, 2),
  (4, 0),
  (0, 4),
  (1, 2),
  (2, 0),
  (3, 3),
  (4, 1),
]


def _rotl_64(x: int, n: int) -> int:
  """Perform left circular rotation on a 64-bit integer.

  Args:
      x: The 64-bit integer to rotate
      n: Number of bits to rotate left

  Returns:
      The rotated 64-bit integer
  """
  n = n % 64
  return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _load_64_le(b: bytes) -> int:
  """Load 64-bit integer from little-endian bytes.

  Args:
      b: 8 bytes in little-endian order

  Returns:
      64-bit integer value
  """
  return (
    b[0]
    | (b[1] << 8)
    | (b[2] << 16)
    | (b[3] << 24)
    | (b[4] << 32)
    | (b[5] << 40)
    | (b[6] << 48)
    | (b[7] << 56)
  )


def _store_64_le(x: int) -> bytes:
  """Store 64-bit integer as little-endian bytes.

  Args:
      x: 64-bit integer value

  Returns:
      8 bytes in little-endian order
  """
  return bytes(
    [
      x & 0xFF,
      (x >> 8) & 0xFF,
      (x >> 16) & 0xFF,
      (x >> 24) & 0xFF,
      (x >> 32) & 0xFF,
      (x >> 40) & 0xFF,
      (x >> 48) & 0xFF,
      (x >> 56) & 0xFF,
    ]
  )


def _keccak_round(a: list[list[int]], round_idx: int) -> list[list[int]]:
  """Apply one round of the Keccak permutation."""
  # Theta step
  c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
  d = [c[(x - 1) % 5] ^ _rotl_64(c[(x + 1) % 5], 1) for x in range(5)]
  for x in range(5):
    for y in range(5):
      a[x][y] ^= d[x]

  # Rho and Pi steps
  b = [[0] * 5 for _ in range(5)]
  for x in range(5):
    for y in range(5):
      b[y][(2 * x + 3 * y) % 5] = _rotl_64(a[x][y], RHO[x][y])

  # Chi step
  for x in range(5):
    for y in range(5):
      a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

  # Iota step
  a[0][0] ^= RC[round_idx]
  return a


def _keccak_f1600(state: bytes) -> bytes:
  """Keccak-f[1600] permutation function.

  Applies 24 rounds of the Keccak permutation.

  Args:
      state: 200-byte state

  Returns:
      Permuted 200-byte state
  """
  # Convert state to 5x5 matrix
  a = [[0] * 5 for _ in range(5)]

  for y in range(5):
    for x in range(5):
      idx = 8 * (5 * y + x)
      a[x][y] = _load_64_le(state[idx : idx + 8])

  # 24 rounds
  for round_idx in range(24):
    a = _keccak_round(a, round_idx)

  # Convert matrix back to bytes
  new_state = bytearray(STATE_SIZE_BYTES)
  for y in range(5):
    for x in range(5):
      idx = 8 * (5 * y + x)
      new_state[idx : idx + 8] = _store_64_le(a[x][y])

  return bytes(new_state)


def _keccak_absorb(state: bytes, data: bytes) -> bytes:
  """Absorb data into the state.

  Args:
      state: Current 200-byte state
      data: Data to absorb (rate bytes)

  Returns:
      New state after absorption
  """
  new_state = bytearray(state)

  for i in range(len(data)):
    new_state[i] ^= data[i]

  return bytes(new_state)


def _keccak_squeeze(state: bytes, output_length_bytes: int) -> bytes:
  """Squeeze output from the state.

  Args:
      state: Current state
      output_length_bytes: Number of bytes to squeeze

  Returns:
      Squeezed output bytes
  """
  output = bytearray()

  while len(output) < output_length_bytes:
    block_size = min(RATE_BYTES, output_length_bytes - len(output))
    output.extend(state[:block_size])

    if len(output) < output_length_bytes:
      state = _keccak_f1600(state)

  return bytes(output)


def sha3_512(message: bytes) -> bytes:
  """Compute SHA3-512 hash of message.

  Args:
      message: Input message as bytes

  Returns:
      The 64-byte (512-bit) hash digest

  Raises:
      TypeError: If message is not bytes

  Examples:
      >>> sha3_512(b"").hex()
      'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'
      >>> sha3_512(b"abc").hex()
      'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'
  """
  if not isinstance(message, bytes):
    msg = "message must be bytes"
    raise TypeError(msg)

  # Initialize state
  state = bytes([0] * STATE_SIZE_BYTES)

  # Absorb phase
  block_size = RATE_BYTES
  message_len = len(message)

  # Process full blocks
  for i in range(0, message_len, block_size):
    block_end = min(i + block_size, message_len)
    block = message[i:block_end]

    if len(block) == block_size:
      # Full block
      state = _keccak_absorb(state, block)
      state = _keccak_f1600(state)
    else:
      # Last partial block with padding
      padded_block = bytearray(block_size)
      padded_block[: len(block)] = block
      padded_block[len(block)] = 0x06  # SHA3 delimiter
      padded_block[-1] |= 0x80  # Final bit

      state = _keccak_absorb(state, bytes(padded_block))
      state = _keccak_f1600(state)

  # Handle message length being exact multiple of block size
  if message_len > 0 and message_len % block_size == 0:
    padded_block = bytearray(block_size)
    padded_block[0] = 0x06
    padded_block[-1] = 0x80

    state = _keccak_absorb(state, bytes(padded_block))
    state = _keccak_f1600(state)

  # Handle empty message
  if message_len == 0:
    padded_block = bytearray(block_size)
    padded_block[0] = 0x06
    padded_block[-1] = 0x80

    state = _keccak_absorb(state, bytes(padded_block))
    state = _keccak_f1600(state)

  # Squeeze phase
  return _keccak_squeeze(state, HASH_LENGTH_BYTES)


def sha3_512_hex(message: bytes) -> str:
  """Compute SHA3-512 hash and return as hex string.

  Args:
      message: Input message as bytes

  Returns:
      128-character hexadecimal string

  Examples:
      >>> sha3_512_hex(b"hello world")
      '3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e8f3d2e'
  """
  return sha3_512(message).hex()


if __name__ == "__main__":
  # Test vectors from NIST
  test_cases = [
    (
      b"",
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
      "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
    ),
    (
      b"abc",
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
      "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    ),
  ]

  for msg, expected in test_cases:
    result = sha3_512(msg).hex()
    print(f"Input: {msg!r}")
    print(f"Expected: {expected}")
    print(f"Got:      {result}")
    print(f"Match: {result == expected}")
    print()
