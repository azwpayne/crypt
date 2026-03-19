"""SHA3-224 Hash Algorithm Implementation

Implements the SHA3-224 cryptographic hash function as defined in FIPS 202.
Produces a 224-bit (28-byte) hash value using the Keccak-f[1600] permutation.

Features:
- FIPS 202 compliant
- Pure Python implementation
- Uses Keccak sponge construction
- Different internal structure from SHA-2 family (not vulnerable to length extension)

Security Notes:
- SHA3-224 produces a 224-bit (28-byte) hash
- Part of the SHA-3 family based on Keccak
- Different design philosophy from SHA-2 (sponge vs Merkle-Damgard)
- Not vulnerable to length extension attacks
- Suitable for applications requiring 112-bit security level

References:
- FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
- Keccak reference: https://keccak.team/keccak.html
"""

from __future__ import annotations

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
ROTATION_CONSTANTS = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]


def _rotate_left(x: int, n: int, w: int = 64) -> int:
  """Perform left circular rotation on a w-bit integer.

  Args:
      x: The integer to rotate
      n: Number of bits to rotate left
      w: Word size in bits (default: 64)

  Returns:
      The rotated w-bit integer
  """
  return ((x << (n % w)) | (x >> (w - (n % w)))) & ((1 << w) - 1)


def _keccak_f_1600(state: list[list[int]]) -> list[list[int]]:
  """Keccak-f[1600] permutation function.

  Applies 24 rounds of the Keccak permutation to the state.
  Each round consists of theta, rho, pi, chi, and iota steps.

  Args:
      state: 5x5 state matrix of 64-bit words

  Returns:
      The permuted 5x5 state matrix
  """
  w = 64
  for round_num in range(24):
    # Theta step: column parity mixing
    c = [0] * 5
    d = [0] * 5

    for x in range(5):
      c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]

    for x in range(5):
      d[x] = c[(x - 1) % 5] ^ _rotate_left(c[(x + 1) % 5], 1, w)

    for x in range(5):
      for y in range(5):
        state[x][y] ^= d[x]

    # Rho and Pi steps: rotation and rearrangement
    b = [[0] * 5 for _ in range(5)]

    for x in range(5):
      for y in range(5):
        b[y][(2 * x + 3 * y) % 5] = _rotate_left(
          state[x][y], ROTATION_CONSTANTS[x][y], w
        )

    # Chi step: non-linear mixing
    for x in range(5):
      for y in range(5):
        state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

    # Iota step: round constant injection
    state[0][0] ^= RC[round_num]

  return state


def _bytes_to_lanes(message_bytes: bytes) -> list[list[int]]:
  """Convert bytes to 5x5 state matrix (64-bit lanes).

  Args:
      message_bytes: Input bytes to convert

  Returns:
      5x5 state matrix of 64-bit words
  """
  state = [[0] * 5 for _ in range(5)]

  for i in range(len(message_bytes)):
    byte = message_bytes[i]
    x = (i // 8) % 5
    y = (i // 40) % 5
    state[x][y] ^= byte << (8 * (i % 8))

  return state


def _lanes_to_bytes(state: list[list[int]]) -> bytes:
  """Convert 5x5 state matrix to bytes.

  Args:
      state: 5x5 state matrix of 64-bit words

  Returns:
      Bytes representation of the state
  """
  output = bytearray()

  for y in range(5):
    for x in range(5):
      lane = state[x][y]
      for i in range(8):
        output.append((lane >> (8 * i)) & 0xFF)

  return bytes(output)


def _keccak_pad(message: bytes, rate_bits: int) -> bytes:
  """SHA3 padding function (multi-rate padding).

  Applies SHA3-specific padding: 0x06 || 0x00... || 0x80

  Args:
      message: Input message bytes
      rate_bits: Rate in bits (r)

  Returns:
      Padded message bytes
  """
  rate_bytes = rate_bits // 8

  # Add SHA3 suffix: 0x06 (binary: 01 10)
  padded = bytearray(message)
  padded.append(0x06)

  # Pad with zeros until one byte before rate boundary
  while (len(padded) % rate_bytes) != (rate_bytes - 1):
    padded.append(0x00)

  # Final delimiter bit
  padded.append(0x80)

  return bytes(padded)


def _keccak_sponge(
  input_bytes: bytes,
  capacity_bits: int,
  output_bits: int,
  _delimiter: int = 0x06,
) -> bytes:
  """Keccak sponge construction.

  Implements the sponge construction with absorb and squeeze phases.

  Args:
      input_bytes: Input message
      capacity_bits: Capacity in bits (c)
      output_bits: Desired output length in bits
      delimiter: Domain separator (0x06 for SHA3)

  Returns:
      Output hash as bytes
  """
  rate_bits = 1600 - capacity_bits
  rate_bytes = rate_bits // 8
  output_bytes = output_bits // 8

  # Padding
  padded_input = _keccak_pad(input_bytes, rate_bits)

  # Initialize state
  state = [[0] * 5 for _ in range(5)]

  # Absorb phase
  for i in range(0, len(padded_input), rate_bytes):
    block = padded_input[i : i + rate_bytes]
    block_state = _bytes_to_lanes(block)

    # XOR block into state
    for x in range(5):
      for y in range(5):
        state[x][y] ^= block_state[x][y]

    # Apply permutation
    state = _keccak_f_1600(state)

  # Squeeze phase
  output = bytearray()
  while len(output) < output_bytes:
    output_block = _lanes_to_bytes(state)
    output.extend(output_block[: min(rate_bytes, output_bytes - len(output))])

    if len(output) < output_bytes:
      state = _keccak_f_1600(state)

  return bytes(output[:output_bytes])


def sha3_224(message: bytes) -> bytes:
  """Compute SHA3-224 hash of message.

  Args:
      message: Input message as bytes

  Returns:
      The 28-byte (224-bit) hash digest

  Raises:
      TypeError: If message is not bytes

  Examples:
      >>> sha3_224(b"").hex()
      '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7'
      >>> sha3_224(b"abc").hex()
      'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf'
  """
  if not isinstance(message, bytes):
    msg = "message must be bytes"
    raise TypeError(msg)

  # SHA3-224: capacity=448 bits, output=224 bits
  return _keccak_sponge(message, 448, 224, _delimiter=0x06)


def sha3_224_hex(message: bytes) -> str:
  """Compute SHA3-224 hash and return as hex string.

  Args:
      message: Input message as bytes

  Returns:
      56-character hexadecimal string

  Examples:
      >>> sha3_224_hex(b"hello world")
      'dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5'
  """
  return sha3_224(message).hex()


if __name__ == "__main__":
  # Test vectors from NIST
  test_cases = [
    (
      b"",
      bytes.fromhex("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"),
    ),
    (
      b"abc",
      bytes.fromhex("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
    ),
  ]

  for msg, expected in test_cases:
    result = sha3_224(msg)
    print(f"Input: {msg!r}")
    print(f"Expected: {expected.hex()}")
    print(f"Got:      {result.hex()}")
    print(f"Match: {result == expected}")
    print()
