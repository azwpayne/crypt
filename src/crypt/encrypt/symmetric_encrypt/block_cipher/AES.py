# @time    : 2026/1/6 15:54
# @name    : AES.py
# @author  : azwpayne
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : AES (Advanced Encryption Standard) block cipher implementation.
#           Supports AES-128, AES-192, AES-256 with ECB, CBC, and CTR modes.

from typing import Literal

# AES S-box for SubBytes transformation
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Inverse S-box for InvSubBytes transformation
INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

# Round constants for key expansion
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]


def sub_bytes(state: bytearray, inv: bool = False) -> None:
    """
    SubBytes transformation - non-linear byte substitution.

    Each byte in the state is replaced with its corresponding value
    from the S-box (or inverse S-box for decryption).

    Args:
        state: The 16-byte state array to transform (modified in place).
        inv: If True, use inverse S-box for decryption.
    """
    sbox = INV_S_BOX if inv else S_BOX
    for i in range(16):
        state[i] = sbox[state[i]]


def shift_rows(state: bytearray, inv: bool = False) -> None:
    """
    ShiftRows transformation - cyclic shift of rows.

    Row 0: no shift
    Row 1: shift left by 1 (right by 1 for decryption)
    Row 2: shift left by 2 (right by 2 for decryption)
    Row 3: shift left by 3 (right by 3 for decryption)

    Args:
        state: The 16-byte state array to transform (modified in place).
        inv: If True, perform inverse shift for decryption.
    """
    # State is column-major: state[i] is row i%4, column i//4
    # Row 0: indices 0, 4, 8, 12
    # Row 1: indices 1, 5, 9, 13
    # Row 2: indices 2, 6, 10, 14
    # Row 3: indices 3, 7, 11, 15

    if inv:
        # Inverse: shift right
        # Row 1: shift right by 1
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        # Row 2: shift right by 2
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        # Row 3: shift right by 3 (left by 1)
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
    else:
        # Forward: shift left
        # Row 1: shift left by 1
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        # Row 2: shift left by 2
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        # Row 3: shift left by 3 (right by 1)
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _gf_mul(a: int, b: int) -> int:
    """
    Multiply two bytes in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).

    Args:
        a: First byte.
        b: Second byte.

    Returns:
        The product in GF(2^8).
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xff
        if high_bit:
            a ^= 0x1b  # 0x11b without the x^8 term
        b >>= 1
    return result


def mix_columns(state: bytearray, inv: bool = False) -> None:
    """
    MixColumns transformation - column-wise mixing using matrix multiplication.

    Each column is treated as a polynomial and multiplied modulo x^4 + 1
    with a fixed polynomial.

    Args:
        state: The 16-byte state array to transform (modified in place).
        inv: If True, use inverse mixing matrix for decryption.
    """
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]

        if inv:
            # Inverse MixColumns: multiply by [0x0e, 0x0b, 0x0d, 0x09]
            state[i] = _gf_mul(0x0e, a0) ^ _gf_mul(0x0b, a1) ^ _gf_mul(0x0d, a2) ^ _gf_mul(0x09, a3)
            state[i + 1] = _gf_mul(0x09, a0) ^ _gf_mul(0x0e, a1) ^ _gf_mul(0x0b, a2) ^ _gf_mul(0x0d, a3)
            state[i + 2] = _gf_mul(0x0d, a0) ^ _gf_mul(0x09, a1) ^ _gf_mul(0x0e, a2) ^ _gf_mul(0x0b, a3)
            state[i + 3] = _gf_mul(0x0b, a0) ^ _gf_mul(0x0d, a1) ^ _gf_mul(0x09, a2) ^ _gf_mul(0x0e, a3)
        else:
            # Forward MixColumns: multiply by [0x02, 0x03, 0x01, 0x01]
            state[i] = _gf_mul(0x02, a0) ^ _gf_mul(0x03, a1) ^ a2 ^ a3
            state[i + 1] = a0 ^ _gf_mul(0x02, a1) ^ _gf_mul(0x03, a2) ^ a3
            state[i + 2] = a0 ^ a1 ^ _gf_mul(0x02, a2) ^ _gf_mul(0x03, a3)
            state[i + 3] = _gf_mul(0x03, a0) ^ a1 ^ a2 ^ _gf_mul(0x02, a3)


def add_round_key(state: bytearray, round_key: bytes) -> None:
    """
    AddRoundKey transformation - XOR state with round key.

    Args:
        state: The 16-byte state array (modified in place).
        round_key: The 16-byte round key.
    """
    for i in range(16):
        state[i] ^= round_key[i]


def key_expansion(key: bytes) -> list[int]:
    """
    Expand the cipher key into round keys.

    Args:
        key: The cipher key (16, 24, or 32 bytes for AES-128, AES-192, AES-256).

    Returns:
        List of expanded key bytes.
    """
    key_len = len(key)
    if key_len == 16:
        nk, nr = 4, 10  # AES-128
    elif key_len == 24:
        nk, nr = 6, 12  # AES-192
    elif key_len == 32:
        nk, nr = 8, 14  # AES-256
    else:
        raise ValueError(f"Invalid key length: {key_len}. Must be 16, 24, or 32 bytes.")

    # Convert key to list of words (4 bytes each)
    w = [key[i:i + 4] for i in range(0, key_len, 4)]

    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            # RotWord and SubWord
            temp = bytes([S_BOX[b] for b in temp[1:] + temp[:1]])
            # XOR with Rcon
            temp = bytes([temp[j] ^ (RCON[(i // nk) - 1] if j == 0 else 0) for j in range(4)])
        elif nk > 6 and i % nk == 4:
            # Additional SubWord for AES-256
            temp = bytes([S_BOX[b] for b in temp])
        w.append(bytes([w[i - nk][j] ^ temp[j] for j in range(4)]))

    # Flatten to list of bytes
    expanded = []
    for word in w:
        expanded.extend(word)
    return expanded


def _encrypt_block(block: bytes, expanded_key: list[int], nr: int) -> bytes:
    """
    Encrypt a single 16-byte block.

    Args:
        block: The 16-byte plaintext block.
        expanded_key: The expanded key schedule.
        nr: Number of rounds (10 for AES-128, 12 for AES-192, 14 for AES-256).

    Returns:
        The 16-byte ciphertext block.
    """
    state = bytearray(block)

    # Initial round
    add_round_key(state, bytes(expanded_key[0:16]))

    # Main rounds
    for round_num in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, bytes(expanded_key[round_num * 16:(round_num + 1) * 16]))

    # Final round (no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, bytes(expanded_key[nr * 16:(nr + 1) * 16]))

    return bytes(state)


def _decrypt_block(block: bytes, expanded_key: list[int], nr: int) -> bytes:
    """
    Decrypt a single 16-byte block.

    Args:
        block: The 16-byte ciphertext block.
        expanded_key: The expanded key schedule.
        nr: Number of rounds (10 for AES-128, 12 for AES-192, 14 for AES-256).

    Returns:
        The 16-byte plaintext block.
    """
    state = bytearray(block)

    # Initial round
    add_round_key(state, bytes(expanded_key[nr * 16:(nr + 1) * 16]))

    # Main rounds (in reverse)
    for round_num in range(nr - 1, 0, -1):
        shift_rows(state, inv=True)
        sub_bytes(state, inv=True)
        add_round_key(state, bytes(expanded_key[round_num * 16:(round_num + 1) * 16]))
        mix_columns(state, inv=True)

    # Final round
    shift_rows(state, inv=True)
    sub_bytes(state, inv=True)
    add_round_key(state, bytes(expanded_key[0:16]))

    return bytes(state)


def _get_key_params(key: bytes) -> tuple[int, int]:
    """
    Get key parameters (Nk, Nr) based on key length.

    Args:
        key: The cipher key.

    Returns:
        Tuple of (nk, nr) where nk is key length in words and nr is number of rounds.
    """
    key_len = len(key)
    if key_len == 16:
        return 4, 10  # AES-128
    elif key_len == 24:
        return 6, 12  # AES-192
    elif key_len == 32:
        return 8, 14  # AES-256
    else:
        raise ValueError(f"Invalid key length: {key_len}. Must be 16, 24, or 32 bytes.")


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS7 padding to data.

    Args:
        data: The data to pad.
        block_size: The block size (default 16 for AES).

    Returns:
        The padded data.
    """
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS7 padding from data.

    Args:
        data: The padded data.
        block_size: The block size (default 16 for AES).

    Returns:
        The unpadded data.

    Raises:
        ValueError: If padding is invalid.
    """
    if not data:
        raise ValueError("Empty data")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError(f"Invalid padding length: {padding_len}")
    if len(data) < padding_len:
        raise ValueError("Data too short for padding")
    # Verify all padding bytes
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError("Invalid padding bytes")
    return data[:-padding_len]


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES in ECB mode.

    Args:
        plaintext: The data to encrypt (will be PKCS7 padded).
        key: The encryption key (16, 24, or 32 bytes).

    Returns:
        The encrypted ciphertext.
    """
    nk, nr = _get_key_params(key)
    expanded_key = key_expansion(key)

    padded = pkcs7_pad(plaintext)
    ciphertext = bytearray()

    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        ciphertext.extend(_encrypt_block(block, expanded_key, nr))

    return bytes(ciphertext)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES in ECB mode.

    Args:
        ciphertext: The data to decrypt (must be multiple of 16 bytes).
        key: The encryption key (16, 24, or 32 bytes).

    Returns:
        The decrypted plaintext (PKCS7 padding removed).
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")

    nk, nr = _get_key_params(key)
    expanded_key = key_expansion(key)

    plaintext = bytearray()

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext.extend(_decrypt_block(block, expanded_key, nr))

    return pkcs7_unpad(bytes(plaintext))


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt data using AES in CBC mode.

    Args:
        plaintext: The data to encrypt (will be PKCS7 padded).
        key: The encryption key (16, 24, or 32 bytes).
        iv: The initialization vector (16 bytes).

    Returns:
        The encrypted ciphertext.
    """
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    nk, nr = _get_key_params(key)
    expanded_key = key_expansion(key)

    padded = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    prev_block = iv

    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        # XOR with previous ciphertext block (or IV for first block)
        xored = bytes([block[j] ^ prev_block[j] for j in range(16)])
        encrypted = _encrypt_block(xored, expanded_key, nr)
        ciphertext.extend(encrypted)
        prev_block = encrypted

    return bytes(ciphertext)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt data using AES in CBC mode.

    Args:
        ciphertext: The data to decrypt (must be multiple of 16 bytes).
        key: The encryption key (16, 24, or 32 bytes).
        iv: The initialization vector (16 bytes).

    Returns:
        The decrypted plaintext (PKCS7 padding removed).
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    nk, nr = _get_key_params(key)
    expanded_key = key_expansion(key)

    plaintext = bytearray()
    prev_block = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted = _decrypt_block(block, expanded_key, nr)
        # XOR with previous ciphertext block (or IV for first block)
        xored = bytes([decrypted[j] ^ prev_block[j] for j in range(16)])
        plaintext.extend(xored)
        prev_block = block

    return pkcs7_unpad(bytes(plaintext))


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Encrypt or decrypt data using AES in CTR mode.

    CTR mode is symmetric - encryption and decryption use the same operation.

    Args:
        data: The data to encrypt or decrypt.
        key: The encryption key (16, 24, or 32 bytes).
        nonce: The nonce/IV (16 bytes total: 8-byte nonce + 8-byte counter,
               or any 16-byte value where the last 8 bytes form the counter).

    Returns:
        The encrypted or decrypted data.
    """
    if len(nonce) != 16:
        raise ValueError("Nonce must be 16 bytes")

    nk, nr = _get_key_params(key)
    expanded_key = key_expansion(key)

    result = bytearray()
    counter = int.from_bytes(nonce[8:], 'big')
    nonce_prefix = nonce[:8]

    for i in range(0, len(data), 16):
        # Create counter block
        counter_block = nonce_prefix + counter.to_bytes(8, 'big')
        keystream = _encrypt_block(counter_block, expanded_key, nr)

        # XOR with plaintext/ciphertext
        block = data[i:i + 16]
        for j in range(len(block)):
            result.append(block[j] ^ keystream[j])

        counter = (counter + 1) & 0xffffffffffffffff

    return bytes(result)


def aes_encrypt(
    plaintext: bytes,
    key: bytes,
    mode: Literal['ecb', 'cbc', 'ctr'] = 'ecb',
    iv: bytes | None = None,
) -> bytes:
    """
    Encrypt data using AES.

    Args:
        plaintext: The data to encrypt.
        key: The encryption key (16, 24, or 32 bytes).
        mode: The encryption mode ('ecb', 'cbc', or 'ctr').
        iv: The initialization vector (required for CBC, optional for others).
            For CTR mode, this is the nonce (16 bytes).

    Returns:
        The encrypted ciphertext.
    """
    if mode == 'ecb':
        return aes_ecb_encrypt(plaintext, key)
    elif mode == 'cbc':
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        return aes_cbc_encrypt(plaintext, key, iv)
    elif mode == 'ctr':
        if iv is None:
            raise ValueError("Nonce is required for CTR mode")
        return aes_ctr_crypt(plaintext, key, iv)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def aes_decrypt(
    ciphertext: bytes,
    key: bytes,
    mode: Literal['ecb', 'cbc', 'ctr'] = 'ecb',
    iv: bytes | None = None,
) -> bytes:
    """
    Decrypt data using AES.

    Args:
        ciphertext: The data to decrypt.
        key: The encryption key (16, 24, or 32 bytes).
        mode: The encryption mode ('ecb', 'cbc', or 'ctr').
        iv: The initialization vector (required for CBC, optional for others).
            For CTR mode, this is the nonce (16 bytes).

    Returns:
        The decrypted plaintext.
    """
    if mode == 'ecb':
        return aes_ecb_decrypt(ciphertext, key)
    elif mode == 'cbc':
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        return aes_cbc_decrypt(ciphertext, key, iv)
    elif mode == 'ctr':
        if iv is None:
            raise ValueError("Nonce is required for CTR mode")
        return aes_ctr_crypt(ciphertext, key, iv)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


if __name__ == '__main__':
    # Test vectors
    key = b'sxyz.blog foobar'
    plaintext = b'Gonna find the answer, how to clear this up'

    # ECB mode test
    enc = aes_ecb_encrypt(plaintext, key)
    dec = aes_ecb_decrypt(enc, key)
    print('ECB Encrypted:', enc.hex())
    print('ECB Decrypted:', dec)

    # CBC mode test
    iv = b'1234567890123456'
    enc_cbc = aes_cbc_encrypt(plaintext, key, iv)
    dec_cbc = aes_cbc_decrypt(enc_cbc, key, iv)
    print('CBC Encrypted:', enc_cbc.hex())
    print('CBC Decrypted:', dec_cbc)

    # CTR mode test
    nonce = b'1234567890123456'
    enc_ctr = aes_ctr_crypt(plaintext, key, nonce)
    dec_ctr = aes_ctr_crypt(enc_ctr, key, nonce)
    print('CTR Encrypted:', enc_ctr.hex())
    print('CTR Decrypted:', dec_ctr)
