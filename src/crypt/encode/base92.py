"""Base92 encoding/decoding implementation.

Base92 uses a 92-character alphabet (printable ASCII excluding space, double quote,
and backtick). The tilde (~) is used as a special denotation for empty string.

Reference: https://base92.sourceforge.net/

Example:
    >>> from crypt.encode.base92 import base92_encode, base92_decode
    >>> encoded = base92_encode(b"Hello, World!")
    >>> decoded = base92_decode(encoded)
    >>> print(decoded)
    b'Hello, World!'
"""

# @time    : 2026/3/14
# @name    : base92.py
# @author  : azwpayne
# @desc    : Base92 encoding/decoding implementation

BASE92_ALPHABET = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~"
BASE92_ENCODING_TABLE = {char: idx for idx, char in enumerate(BASE92_ALPHABET)}


def base92_encode(input_data: bytes) -> str:
    """
    Encode bytes to base92 string.

    Args:
        input_data: The bytes to encode

    Returns:
        Base92 encoded string
    """
    if not input_data:
        return "~"

    b = 0
    n = 0
    out = []

    for byte in input_data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 90:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(BASE92_ALPHABET[v % 92])
            out.append(BASE92_ALPHABET[v // 92])

    if n:
        out.append(BASE92_ALPHABET[b % 92])
        if n > 7 or b > 90:
            out.append(BASE92_ALPHABET[b // 92])

    return "".join(out)


def base92_decode(encoded_str: str) -> bytes:
    """
    Decode base92 string to bytes.

    Args:
        encoded_str: The base92 encoded string

    Returns:
        Decoded bytes
    """
    if encoded_str == "~":
        return b""

    v = -1
    b = 0
    n = 0
    out = bytearray()

    for char in encoded_str:
        if char not in BASE92_ENCODING_TABLE:
            msg = f"Invalid character in base92 string: {char!r}"
            raise ValueError(msg)
        c = BASE92_ENCODING_TABLE[char]
        if v < 0:
            v = c
        else:
            v += c * 92
            b |= v << n
            n += 13 if (v & 8191) > 90 else 14
            while n > 7:
                out.append(b & 0xFF)
                b >>= 8
                n -= 8
            v = -1

    if v != -1:
        b |= v << n
        out.append(b & 0xFF)

    return bytes(out)


def base92_encode_str(input_str: str, encoding: str = "utf-8") -> str:
    """
    Encode a string to base92.

    Args:
        input_str: The string to encode
        encoding: The text encoding to use

    Returns:
        Base92 encoded string
    """
    return base92_encode(input_str.encode(encoding))


def base92_decode_str(encoded_str: str, encoding: str = "utf-8") -> str:
    """
    Decode base92 string to original string.

    Args:
        encoded_str: The base92 encoded string
        encoding: The text encoding to use

    Returns:
        Decoded string
    """
    return base92_decode(encoded_str).decode(encoding)


# Usage example
if __name__ == "__main__":
    # Basic usage with bytes
    data = b"Hello, Base92!"
    encoded = base92_encode(data)
    decoded = base92_decode(encoded)
    print(f"Original: {data}")
    print(f"Encoded:  {encoded}")
    print(f"Decoded:  {decoded}")
    print(f"Match:    {data == decoded}")

    # String version with Unicode
    text = "Hello, 世界!"
    encoded_text = base92_encode_str(text)
    decoded_text = base92_decode_str(encoded_text)
    print(f"\nText Original: {text}")
    print(f"Text Encoded:  {encoded_text}")
    print(f"Text Decoded:  {decoded_text}")
    print(f"Match:         {text == decoded_text}")
