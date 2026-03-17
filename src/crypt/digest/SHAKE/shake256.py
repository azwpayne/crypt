"""SHAKE256 XOF (Extendable-Output Function) implementation.

SHAKE256 is an extendable-output function based on the Keccak-f[1600] permutation.
It uses a rate of 136 bytes (1088 bits) and capacity of 64 bytes (512 bits).

Domain separator: 0x1F (same as SHAKE128)
"""

# Import from SHA3 implementation
from crypt.digest.SHA.sha3_256 import (
  bytes_to_lanes,
  keccak_f_1600,
  lanes_to_bytes,
)

# SHAKE256 parameters
SHAKE256_RATE = 136  # bytes (1088 bits)
SHAKE256_CAPACITY = 64  # bytes (512 bits)


def shake256_pad(message_len: int, rate: int) -> bytes:
  """SHAKE256 padding function.

  Uses domain separator 0x1F.
  """
  # Calculate padding length
  pad_len = rate - (message_len % rate)
  if pad_len == 0:
    pad_len = rate

  # Create padding bytes
  padding = bytearray(pad_len)
  padding[0] = 0x1F  # SHAKE domain separator
  padding[pad_len - 1] |= 0x80  # End marker

  return bytes(padding)


class SHAKE256:
  """SHAKE256 extendable-output function.

  SHAKE256 is a XOF (Extendable-Output Function) that can produce arbitrary
  output lengths. It is based on the Keccak-f[1600] permutation.

  SHAKE256 has a higher security level than SHAKE128 (256-bit vs 128-bit).

  Usage:
      shake = SHAKE256(b"message")
      output = shake.read(32)  # Get 32 bytes of output

  Or incrementally:
      shake = SHAKE256()
      shake.update(b"part1")
      shake.update(b"part2")
      output = shake.read(64)
  """

  def __init__(self, data: bytes | None = None):
    """Initialize SHAKE256.

    Args:
        data: Optional initial data to absorb.
    """
    self._state = [0] * 25  # 5x5 lanes
    self._buffer = b""  # Unprocessed data buffer
    self._absorbing = True  # Still absorbing data
    self._squeeze_offset = 0  # Offset within current state block during squeezing

    if data:
      self.update(data)

  def update(self, data: bytes) -> "SHAKE256":
    """Absorb more data into the state.

    Args:
        data: Data to absorb.

    Returns:
        Self for method chaining.
    """
    if not self._absorbing:
      msg = "Cannot update after reading output"
      raise ValueError(msg)

    self._buffer += data

    # Process full rate-sized blocks
    while len(self._buffer) >= SHAKE256_RATE:
      block = self._buffer[:SHAKE256_RATE]
      self._buffer = self._buffer[SHAKE256_RATE:]

      # XOR block into state
      block_lanes = bytes_to_lanes(block.ljust(200, b"\x00"))
      for j in range(len(block_lanes)):
        self._state[j] ^= block_lanes[j]

      # Apply Keccak-f
      self._state = keccak_f_1600(self._state)

    return self

  def _finalize(self) -> None:
    """Finalize absorption and switch to squeezing mode."""
    if not self._absorbing:
      return

    # Add padding
    padded_msg = self._buffer + shake256_pad(len(self._buffer), SHAKE256_RATE)

    # Process remaining blocks
    for i in range(0, len(padded_msg), SHAKE256_RATE):
      block = padded_msg[i : i + SHAKE256_RATE]
      block_lanes = bytes_to_lanes(block.ljust(200, b"\x00"))

      for j in range(len(block_lanes)):
        self._state[j] ^= block_lanes[j]

      self._state = keccak_f_1600(self._state)

    self._absorbing = False
    self._buffer = b""
    self._squeeze_offset = 0

  def read(self, length: int) -> bytes:
    """Squeeze output of specified length.

    Args:
        length: Number of bytes to output.

    Returns:
        The squeezed output bytes.
    """
    if length < 0:
      msg = "Length must be non-negative"
      raise ValueError(msg)

    if length == 0:
      return b""

    # Finalize if still absorbing
    if self._absorbing:
      self._finalize()

    output = bytearray()

    while len(output) < length:
      # Get more bytes from state
      state_bytes = lanes_to_bytes(self._state)

      # Calculate how many bytes we can take from current state
      available_in_state = SHAKE256_RATE - self._squeeze_offset
      needed = length - len(output)
      to_take = min(available_in_state, needed)

      output.extend(state_bytes[self._squeeze_offset : self._squeeze_offset + to_take])
      self._squeeze_offset += to_take

      # If we've exhausted the current state block, apply Keccak-f
      if self._squeeze_offset >= SHAKE256_RATE:
        self._state = keccak_f_1600(self._state)
        self._squeeze_offset = 0

    return bytes(output)

  def hexdigest(self, length: int) -> str:
    """Get hex representation of output.

    Args:
        length: Number of bytes to output.

    Returns:
        Hexadecimal string of the output.
    """
    return self.read(length).hex()

  def copy(self) -> "SHAKE256":
    """Create a copy of the current state.

    Returns:
        A new SHAKE256 instance with the same state.
    """
    new_shake = SHAKE256.__new__(SHAKE256)
    new_shake._state = self._state.copy()
    new_shake._buffer = self._buffer
    new_shake._absorbing = self._absorbing
    new_shake._squeeze_offset = self._squeeze_offset
    return new_shake


def shake256(data: bytes, length: int) -> bytes:
  """Convenience function for one-shot SHAKE256 computation.

  Args:
      data: Input data.
      length: Output length in bytes.

  Returns:
      The SHAKE256 output.
  """
  return SHAKE256(data).read(length)


def shake256_hex(data: bytes, length: int) -> str:
  """Convenience function for one-shot SHAKE256 hex output.

  Args:
      data: Input data.
      length: Output length in bytes.

  Returns:
      The SHAKE256 output as a hex string.
  """
  return SHAKE256(data).hexdigest(length)


def test_shake256():
  """Basic tests for SHAKE256."""
  # Test empty message
  shake = SHAKE256(b"")
  result = shake.read(32)
  assert len(result) == 32

  # Test basic message
  shake = SHAKE256(b"abc")
  result = shake.read(32)
  assert len(result) == 32

  # Test various lengths
  for length in [16, 32, 64, 128]:
    shake = SHAKE256(b"test")
    result = shake.read(length)
    assert len(result) == length

  # Test copy
  shake1 = SHAKE256(b"test")
  _ = shake1.read(16)
  shake2 = shake1.copy()
  result1 = shake1.read(32)
  result2 = shake2.read(32)
  assert result1 == result2

  print("All SHAKE256 tests passed!")


if __name__ == "__main__":
  test_shake256()
