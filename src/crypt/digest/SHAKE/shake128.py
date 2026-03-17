"""SHAKE128 XOF (Extendable-Output Function) implementation.

SHAKE128 is an extendable-output function based on the Keccak-f[1600] permutation.
It uses a rate of 168 bytes (1344 bits) and capacity of 32 bytes (256 bits).

Domain separator: 0x1F (different from SHA3's 0x06)
"""

import struct
from typing import Optional

# Import from SHA3 implementation
from crypt.digest.SHA.sha3_256 import (
    keccak_f_1600,
    bytes_to_lanes,
    lanes_to_bytes,
    KECCAK_F_ROUNDS,
)

# SHAKE128 parameters
SHAKE128_RATE = 168  # bytes (1344 bits)
SHAKE128_CAPACITY = 32  # bytes (256 bits)


def shake128_pad(message_len: int, rate: int) -> bytes:
    """SHAKE128 padding function.

    Uses domain separator 0x1F instead of SHA3's 0x06.
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


class SHAKE128:
    """SHAKE128 extendable-output function.

    SHAKE128 is a XOF (Extendable-Output Function) that can produce arbitrary
    output lengths. It is based on the Keccak-f[1600] permutation.

    Usage:
        shake = SHAKE128(b"message")
        output = shake.read(32)  # Get 32 bytes of output

    Or incrementally:
        shake = SHAKE128()
        shake.update(b"part1")
        shake.update(b"part2")
        output = shake.read(64)
    """

    def __init__(self, data: Optional[bytes] = None):
        """Initialize SHAKE128.

        Args:
            data: Optional initial data to absorb.
        """
        self._state = [0] * 25  # 5x5 lanes
        self._buffer = b""  # Unprocessed data buffer
        self._absorbing = True  # Still absorbing data
        self._squeeze_offset = 0  # Offset within current state block during squeezing

        if data:
            self.update(data)

    def update(self, data: bytes) -> "SHAKE128":
        """Absorb more data into the state.

        Args:
            data: Data to absorb.

        Returns:
            Self for method chaining.
        """
        if not self._absorbing:
            raise ValueError("Cannot update after reading output")

        self._buffer += data

        # Process full rate-sized blocks
        while len(self._buffer) >= SHAKE128_RATE:
            block = self._buffer[:SHAKE128_RATE]
            self._buffer = self._buffer[SHAKE128_RATE:]

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
        padded_msg = self._buffer + shake128_pad(len(self._buffer), SHAKE128_RATE)

        # Process remaining blocks
        for i in range(0, len(padded_msg), SHAKE128_RATE):
            block = padded_msg[i:i + SHAKE128_RATE]
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
            raise ValueError("Length must be non-negative")

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
            available_in_state = SHAKE128_RATE - self._squeeze_offset
            needed = length - len(output)
            to_take = min(available_in_state, needed)

            output.extend(state_bytes[self._squeeze_offset:self._squeeze_offset + to_take])
            self._squeeze_offset += to_take

            # If we've exhausted the current state block, apply Keccak-f
            if self._squeeze_offset >= SHAKE128_RATE:
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

    def copy(self) -> "SHAKE128":
        """Create a copy of the current state.

        Returns:
            A new SHAKE128 instance with the same state.
        """
        import copy

        new_shake = SHAKE128.__new__(SHAKE128)
        new_shake._state = self._state.copy()
        new_shake._buffer = self._buffer
        new_shake._absorbing = self._absorbing
        new_shake._squeeze_offset = self._squeeze_offset
        return new_shake


def shake128(data: bytes, length: int) -> bytes:
    """Convenience function for one-shot SHAKE128 computation.

    Args:
        data: Input data.
        length: Output length in bytes.

    Returns:
        The SHAKE128 output.
    """
    return SHAKE128(data).read(length)


def shake128_hex(data: bytes, length: int) -> str:
    """Convenience function for one-shot SHAKE128 hex output.

    Args:
        data: Input data.
        length: Output length in bytes.

    Returns:
        The SHAKE128 output as a hex string.
    """
    return SHAKE128(data).hexdigest(length)


def test_shake128():
    """Basic tests for SHAKE128."""
    # Test empty message
    shake = SHAKE128(b"")
    result = shake.read(32)
    assert len(result) == 32

    # Test basic message
    shake = SHAKE128(b"abc")
    result = shake.read(32)
    assert len(result) == 32

    # Test various lengths
    for length in [16, 32, 64, 128]:
        shake = SHAKE128(b"test")
        result = shake.read(length)
        assert len(result) == length

    # Test copy
    shake1 = SHAKE128(b"test")
    _ = shake1.read(16)
    shake2 = shake1.copy()
    result1 = shake1.read(32)
    result2 = shake2.read(32)
    assert result1 == result2

    print("All SHAKE128 tests passed!")


if __name__ == "__main__":
    test_shake128()
