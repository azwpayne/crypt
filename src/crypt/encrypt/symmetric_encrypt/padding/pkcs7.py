"""PKCS#7 padding implementation for block ciphers.

PKCS#7 padding adds N bytes of value N to make the data a multiple of block_size.
If the data is already a multiple of block_size, a full block of padding is added.
"""


def pad(data: bytes, block_size: int) -> bytes:
  """Add PKCS#7 padding to data.

  Args:
      data: The data to pad.
      block_size: The block size (must be 1-255).

  Returns:
      The padded data.

  Raises:
      ValueError: If block_size is not in the range 1-255.
  """
  if not 1 <= block_size <= 255:
    msg = f"block_size must be between 1 and 255, got {block_size}"
    raise ValueError(msg)

  padding_len = block_size - (len(data) % block_size)
  padding = bytes([padding_len]) * padding_len
  return data + padding


def unpad(data: bytes, block_size: int) -> bytes:
  """Remove PKCS#7 padding from data.

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
    msg = f"block_size must be between 1 and 255, got {block_size}"
    raise ValueError(msg)

  if not data:
    msg = "Data is empty"
    raise ValueError(msg)

  padding_len = data[-1]

  # Validate padding length
  if padding_len == 0 or padding_len > block_size:
    msg = f"Invalid padding length: {padding_len}"
    raise ValueError(msg)

  if len(data) < padding_len:
    msg = "Data too short for padding"
    raise ValueError(msg)

  # Constant-time verification of all padding bytes
  padding = data[-padding_len:]
  expected_padding = bytes([padding_len]) * padding_len

  # Use constant-time comparison to avoid timing attacks
  if not _constant_time_compare(padding, expected_padding):
    msg = "Invalid padding bytes"
    raise ValueError(msg)

  return data[:-padding_len]


def _constant_time_compare(a: bytes, b: bytes) -> bool:
  """Compare two byte strings in constant time.

  This prevents timing attacks by ensuring the comparison takes
  the same amount of time regardless of where the bytes differ.
  """
  if len(a) != len(b):
    return False

  result = 0
  for x, y in zip(a, b, strict=False):
    result |= x ^ y

  return result == 0


def test_pkcs7():
  """Basic tests for PKCS#7 padding."""
  # Test empty data
  assert pad(b"", 16) == b"\x10" * 16

  # Test short data
  assert pad(b"hello", 16) == b"hello" + b"\x0b" * 11

  # Test exact block
  assert pad(b"a" * 16, 16) == b"a" * 16 + b"\x10" * 16

  # Test 8-byte block (DES)
  assert pad(b"hello", 8) == b"hello" + b"\x03" * 3

  # Test round-trip
  data = b"secret message"
  padded = pad(data, 16)
  assert unpad(padded, 16) == data

  # Test full block round-trip
  data = b"a" * 16
  padded = pad(data, 16)
  assert unpad(padded, 16) == data

  print("All PKCS#7 tests passed!")


if __name__ == "__main__":
  test_pkcs7()
