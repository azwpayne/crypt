"""Pure Python implementation of IDEA (International Data Encryption Algorithm).

IDEA is a 64-bit block cipher with 128-bit keys, using 8.5 rounds (8 full rounds
plus an output transformation). It uses the Lai-Massey scheme with three operations:
- Modular multiplication (mod 2^16+1)
- Modular addition (mod 2^16)
- Bitwise XOR

This implementation is for educational purposes only.
"""

from __future__ import annotations

from typing import Final

# IDEA constants
BLOCK_SIZE: Final[int] = 8  # 64 bits
KEY_SIZE: Final[int] = 16  # 128 bits
ROUNDS: Final[int] = 8


def _mul(a: int, b: int) -> int:
    """Modular multiplication mod 2^16+1.

    Treats 0 as 2^16 for multiplication purposes.
    """
    if a == 0:
        a = 0x10000
    if b == 0:
        b = 0x10000
    result = (a * b) % 0x10001
    return result if result != 0x10000 else 0


def _mul_inv(x: int) -> int:
    """Modular multiplicative inverse mod 2^16+1."""
    if x == 0:
        return 0
    return pow(x, 0x10001 - 2, 0x10001)


def _add_inv(x: int) -> int:
    """Additive inverse mod 2^16."""
    return (-x) & 0xFFFF


def key_schedule(key: bytes) -> list[int]:
    """Generate 52 16-bit subkeys from 128-bit key.

    Args:
        key: 16-byte key

    Returns:
        List of 52 subkeys
    """
    if len(key) != 16:
        msg = f"Key must be 16 bytes, got {len(key)}"
        raise ValueError(msg)

    # Convert key to 8 16-bit words
    key_words = [int.from_bytes(key[i: i + 2], "big") for i in range(0, 16, 2)]

    subkeys = []
    for i in range(52):
        # Get key from current position
        word_idx = i % 8
        subkeys.append(key_words[word_idx])

        # Rotate key words every 8 subkeys
        if word_idx == 7:
            # 25-bit left rotation of the 128-bit key
            val = int.from_bytes(b"".join(w.to_bytes(2, "big") for w in key_words),
                                 "big")
            val = ((val << 25) | (val >> 103)) & ((1 << 128) - 1)
            key_bytes = val.to_bytes(16, "big")
            key_words = [int.from_bytes(key_bytes[i: i + 2], "big") for i in
                         range(0, 16, 2)]

    return subkeys


def _idea_round(
        x1: int, x2: int, x3: int, x4: int, subkeys: list[int]
) -> tuple[int, int, int, int]:
    """Single IDEA round.

    Args:
        x1, x2, x3, x4: 16-bit input words
        subkeys: 6 subkeys for this round

    Returns:
        Four 16-bit output words
    """
    k1, k2, k3, k4, k5, k6 = subkeys[:6]

    # Step 1: Multiply x1 with k1, add k2 to x2, add k3 to x3, multiply x4 with k4
    a = _mul(x1, k1)
    b = (x2 + k2) & 0xFFFF
    c = (x3 + k3) & 0xFFFF
    d = _mul(x4, k4)

    # Step 2: XOR the results
    e = a ^ c
    f = b ^ d

    # Step 3: Multiply e with k5, add the result to f, multiply with k6
    g = _mul(e, k5)
    h = (g + f) & 0xFFFF
    i = _mul(h, k6)
    j = (g + i) & 0xFFFF

    # Step 4: XOR the results
    y1 = a ^ i
    y2 = c ^ i
    y3 = b ^ j
    y4 = d ^ j

    return y1, y2, y3, y4


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt single 8-byte block.

    Args:
        block: 8-byte plaintext
        key: 16-byte key

    Returns:
        8-byte ciphertext
    """
    if len(block) != 8:
        msg = f"Block must be 8 bytes, got {len(block)}"
        raise ValueError(msg)

    subkeys = key_schedule(key)

    # Split into 4 16-bit words
    x1 = int.from_bytes(block[0:2], "big")
    x2 = int.from_bytes(block[2:4], "big")
    x3 = int.from_bytes(block[4:6], "big")
    x4 = int.from_bytes(block[6:8], "big")

    # 8 rounds
    for round_idx in range(8):
        sk = subkeys[round_idx * 6: (round_idx + 1) * 6]
        x1, x2, x3, x4 = _idea_round(x1, x2, x3, x4, sk)
        # Swap middle two words for next round
        x2, x3 = x3, x2

    # Output transformation (swap back first)
    x2, x3 = x3, x2

    # Final half-round: no swap, no MA structure
    k1, k2, k3, k4 = subkeys[48:52]
    y1 = _mul(x1, k1)
    y2 = (x2 + k2) & 0xFFFF
    y3 = (x3 + k3) & 0xFFFF
    y4 = _mul(x4, k4)

    # Combine into output
    return (
            y1.to_bytes(2, "big")
            + y2.to_bytes(2, "big")
            + y3.to_bytes(2, "big")
            + y4.to_bytes(2, "big")
    )


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt single 8-byte block.

    Args:
        block: 8-byte ciphertext
        key: 16-byte key

    Returns:
        8-byte plaintext
    """
    if len(block) != 8:
        msg = f"Block must be 8 bytes, got {len(block)}"
        raise ValueError(msg)

    subkeys = key_schedule(key)

    # Build inverse key schedule according to IDEA specification
    # The decryption subkeys are computed as follows:
    # - First 4 subkeys for inverse output transformation
    # - Then 8 rounds of 6 subkeys each, in reverse order

    dk = [0] * 52

    # Inverse output transformation keys (these undo the final encryption step)
    # dk[0:4] = k49^-1, -k50, -k51, k52^-1
    dk[0] = _mul_inv(subkeys[48])  # k49^-1
    dk[1] = _add_inv(subkeys[49])  # -k50
    dk[2] = _add_inv(subkeys[50])  # -k51
    dk[3] = _mul_inv(subkeys[51])  # k52^-1

    # Inverse round keys for rounds 8 down to 1
    # For encryption round r (1-indexed), the 6 subkeys are:
    #   k1, k2, k3, k4, k5, k6
    # For decryption, the corresponding round uses:
    #   k1^-1, -k3, -k2, k4^-1, k5, k6
    # But note the swap of k2 and k3 positions!

    for i in range(8):
        # Encryption round index (0-based, from first to last)
        enc_round = 7 - i
        # Decryption round index (0-based, applied in order)
        dec_round = i

        enc_base = enc_round * 6
        dec_base = 4 + dec_round * 6

        # Decryption subkeys for this round
        dk[dec_base] = _mul_inv(subkeys[enc_base])  # k1^-1
        dk[dec_base + 1] = _add_inv(subkeys[enc_base + 2])  # -k3 (position swapped)
        dk[dec_base + 2] = _add_inv(subkeys[enc_base + 1])  # -k2 (position swapped)
        dk[dec_base + 3] = _mul_inv(subkeys[enc_base + 3])  # k4^-1
        dk[dec_base + 4] = subkeys[enc_base + 4]  # k5
        dk[dec_base + 5] = subkeys[enc_base + 5]  # k6

    # Now apply decryption using dk
    # Split ciphertext into 4 16-bit words
    x1 = int.from_bytes(block[0:2], "big")
    x2 = int.from_bytes(block[2:4], "big")
    x3 = int.from_bytes(block[4:6], "big")
    x4 = int.from_bytes(block[6:8], "big")

    # Apply inverse output transformation (using dk[0:4])
    y1 = _mul(x1, dk[0])
    y2 = (x2 + dk[1]) & 0xFFFF
    y3 = (x3 + dk[2]) & 0xFFFF
    y4 = _mul(x4, dk[3])
    x1, x2, x3, x4 = y1, y2, y3, y4

    # Apply 8 inverse rounds (in reverse order of how they're applied in encryption)
    # Encryption applies rounds 0,1,2,3,4,5,6,7 with swap after each
    # So we need to apply inverse rounds in reverse: 7,6,5,4,3,2,1,0
    for round_idx in range(7, -1, -1):
        # Swap middle words first (undoing encryption's swap between rounds)
        x2, x3 = x3, x2
        sk = dk[4 + round_idx * 6: 4 + (round_idx + 1) * 6]
        x1, x2, x3, x4 = _idea_round(x1, x2, x3, x4, sk)

    # Final swap to restore original word order
    x2, x3 = x3, x2

    return (
            x1.to_bytes(2, "big")
            + x2.to_bytes(2, "big")
            + x3.to_bytes(2, "big")
            + x4.to_bytes(2, "big")
    )


# PKCS7 padding helpers
def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Pad data using PKCS7."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    if not data:
        return data
    padding_len = data[-1]
    if padding_len > len(data) or padding_len == 0:
        return data
    return data[:-padding_len]


def idea_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using IDEA in ECB mode."""
    padded = _pkcs7_pad(data, BLOCK_SIZE)
    result = b""
    for i in range(0, len(padded), BLOCK_SIZE):
        result += encrypt_block(padded[i: i + BLOCK_SIZE], key)
    return result


def idea_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt data using IDEA in ECB mode."""
    result = b""
    for i in range(0, len(data), BLOCK_SIZE):
        result += decrypt_block(data[i: i + BLOCK_SIZE], key)
    return _pkcs7_unpad(result)


def idea_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using IDEA in CBC mode."""
    if len(iv) != BLOCK_SIZE:
        msg = f"IV must be {BLOCK_SIZE} bytes"
        raise ValueError(msg)

    padded = _pkcs7_pad(data, BLOCK_SIZE)
    result = b""
    prev = iv

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i: i + BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, prev, strict=False))
        encrypted = encrypt_block(xored, key)
        result += encrypted
        prev = encrypted

    return result


def idea_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using IDEA in CBC mode."""
    if len(iv) != BLOCK_SIZE:
        msg = f"IV must be {BLOCK_SIZE} bytes"
        raise ValueError(msg)

    result = b""
    prev = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i: i + BLOCK_SIZE]
        decrypted = decrypt_block(block, key)
        xored = bytes(a ^ b for a, b in zip(decrypted, prev, strict=False))
        result += xored
        prev = block

    return _pkcs7_unpad(result)
