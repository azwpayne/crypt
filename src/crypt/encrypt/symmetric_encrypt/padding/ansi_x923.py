"""ANSI X.923 padding implementation for block ciphers.

ANSI X.923 padding adds zeros followed by a byte with the padding length
to make the data a multiple of block_size.
If the data is already a multiple of block_size, a full block of padding is added.

Example for block_size=8, data="hello" (5 bytes):
- Padding needed: 3 bytes
- Padding bytes: \x00\x00\x03

Key difference from PKCS#7:
- PKCS#7: All padding bytes = padding length (e.g., \x03\x03\x03)
- ANSI X.923: Zeros + last byte = length (e.g., \x00\x00\x03)
"""


def pad(data: bytes, block_size: int) -> bytes:
    """Add ANSI X.923 padding to data.

    Args:
        data: The data to pad.
        block_size: The block size (must be 1-255).

    Returns:
        The padded data.

    Raises:
        ValueError: If block_size is not in the range 1-255.
    """
    if not 1 <= block_size <= 255:
        raise ValueError(f"block_size must be between 1 and 255, got {block_size}")

    padding_len = block_size - (len(data) % block_size)
    # ANSI X.923: zeros for all padding bytes except the last one
    padding = b"\x00" * (padding_len - 1) + bytes([padding_len])
    return data + padding


def unpad(data: bytes, block_size: int) -> bytes:
    """Remove ANSI X.923 padding from data.

    Args:
        data: The padded data.
        block_size: The block size (must be 1-255).

    Returns:
        The unpadded data.

    Raises:
        ValueError: If block_size is not in the range 1-255.
        ValueError: If data is empty.
        ValueError: If padding is invalid.
    """
    if not 1 <= block_size <= 255:
        raise ValueError(f"block_size must be between 1 and 255, got {block_size}")

    if not data:
        raise ValueError("data is empty")

    padding_len = data[-1]

    # Validate padding length
    if padding_len == 0 or padding_len > block_size:
        raise ValueError("invalid padding")

    if len(data) < padding_len:
        raise ValueError("invalid padding length")

    # Verify all padding bytes (except last) are zeros
    padding = data[-padding_len:]
    expected_padding = b"\x00" * (padding_len - 1) + bytes([padding_len])

    # Use constant-time comparison to avoid timing attacks
    if not _constant_time_compare(padding, expected_padding):
        raise ValueError("invalid padding bytes")

    return data[:-padding_len]


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.

    This prevents timing attacks by ensuring the comparison takes
    the same amount of time regardless of where the bytes differ.
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y

    return result == 0


def test_ansi_x923():
    """Basic tests for ANSI X.923 padding."""
    # Test empty data
    assert pad(b"", 16) == b"\x00" * 15 + b"\x10"

    # Test short data
    assert pad(b"hello", 16) == b"hello" + b"\x00" * 10 + b"\x0b"

    # Test exact block
    assert pad(b"a" * 16, 16) == b"a" * 16 + b"\x00" * 15 + b"\x10"

    # Test 8-byte block (DES)
    assert pad(b"hello", 8) == b"hello" + b"\x00" * 2 + b"\x03"

    # Test round-trip
    data = b"secret message"
    padded = pad(data, 16)
    assert unpad(padded, 16) == data

    # Test full block round-trip
    data = b"a" * 16
    padded = pad(data, 16)
    assert unpad(padded, 16) == data

    print("All ANSI X.923 tests passed!")


if __name__ == "__main__":
    test_ansi_x923()
