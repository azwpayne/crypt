"""ECB (Electronic Codebook) mode implementation.

WARNING: ECB mode is not secure for most applications because identical plaintext
blocks produce identical ciphertext blocks, revealing patterns in the data.
This implementation is provided for educational purposes only.
"""

import warnings
from typing import Callable

from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _encrypt_block,
    _decrypt_block,
    key_expansion,
    _get_key_params,
)
from crypt.encrypt.symmetric_encrypt.padding.pkcs7 import pad, unpad


class ECBMode:
    """ECB (Electronic Codebook) mode of operation.

    ECB encrypts each block of plaintext independently using the same key.
    This is insecure for most applications because:
    - Identical plaintext blocks produce identical ciphertext blocks
    - Patterns in the plaintext are visible in the ciphertext

    Use CBC, CTR, or GCM modes for secure encryption.

    Attributes:
        block_size: The block size in bytes (16 for AES).
        key: The encryption key.
        expanded_key: The expanded key schedule.
        nr: Number of rounds.
    """

    def __init__(
        self,
        encrypt_func: Callable[[bytes], bytes] | None = None,
        decrypt_func: Callable[[bytes], bytes] | None = None,
        block_size: int = 16,
        key: bytes | None = None,
        expanded_key: list[int] | None = None,
        nr: int | None = None,
    ):
        """Initialize ECB mode.

        Args:
            encrypt_func: Optional external encrypt function.
            decrypt_func: Optional external decrypt function.
            block_size: The block size in bytes (default 16 for AES).
            key: The encryption key (required if using AES).
            expanded_key: Pre-computed expanded key (optional).
            nr: Number of rounds (optional, derived from key if not provided).

        Raises:
            ValueError: If key is not provided and no external functions are given.
        """
        warnings.warn(
            "ECB mode is not secure for most applications. "
            "Identical plaintext blocks produce identical ciphertext blocks, "
            "revealing patterns in the data. Use CBC, CTR, or GCM modes instead.",
            UserWarning,
            stacklevel=2,
        )

        self.block_size = block_size
        self._encrypt_func = encrypt_func
        self._decrypt_func = decrypt_func

        # If key is provided, use AES
        if key is not None:
            self.key = key
            nk, self.nr = _get_key_params(key)
            self.expanded_key = expanded_key if expanded_key is not None else key_expansion(key)
        elif expanded_key is not None and nr is not None:
            self.key = None
            self.expanded_key = expanded_key
            self.nr = nr
        elif encrypt_func is None or decrypt_func is None:
            msg = "Either key or both encrypt_func and decrypt_func must be provided"
            raise ValueError(msg)
        else:
            self.key = None
            self.expanded_key = []
            self.nr = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using ECB mode.

        Args:
            plaintext: The data to encrypt.

        Returns:
            The encrypted ciphertext.
        """
        # PKCS7 pad the plaintext
        padded = pad(plaintext, self.block_size)

        # Encrypt block by block
        ciphertext = bytearray()
        for i in range(0, len(padded), self.block_size):
            block = padded[i : i + self.block_size]
            if self._encrypt_func is not None:
                encrypted_block = self._encrypt_func(block)
            else:
                encrypted_block = _encrypt_block(block, self.expanded_key, self.nr)
            ciphertext.extend(encrypted_block)

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using ECB mode.

        Args:
            ciphertext: The data to decrypt.

        Returns:
            The decrypted plaintext.

        Raises:
            ValueError: If ciphertext length is not a multiple of block_size.
        """
        # Validate ciphertext length
        if len(ciphertext) % self.block_size != 0:
            msg = f"Ciphertext length must be a multiple of block_size ({self.block_size})"
            raise ValueError(msg)

        # Decrypt block by block
        plaintext = bytearray()
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i : i + self.block_size]
            if self._decrypt_func is not None:
                decrypted_block = self._decrypt_func(block)
            else:
                decrypted_block = _decrypt_block(block, self.expanded_key, self.nr)
            plaintext.extend(decrypted_block)

        # PKCS7 unpad
        return unpad(bytes(plaintext), self.block_size)


def test_ecb_mode():
    """Basic tests for ECB mode."""
    import warnings

    key = b"0123456789abcdef"

    # Suppress warning for tests
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        ecb = ECBMode(key=key)

    # Test basic encryption/decryption
    plaintext = b"Hello, World!"
    ciphertext = ecb.encrypt(plaintext)
    decrypted = ecb.decrypt(ciphertext)
    assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

    # Test empty data
    empty = b""
    ciphertext = ecb.encrypt(empty)
    decrypted = ecb.decrypt(ciphertext)
    assert decrypted == empty

    # Test exact block size
    exact_block = b"a" * 16
    ciphertext = ecb.encrypt(exact_block)
    assert len(ciphertext) == 32  # 2 blocks due to padding
    decrypted = ecb.decrypt(ciphertext)
    assert decrypted == exact_block

    # Test multi-block data
    multi_block = b"This is a test message that is longer than one block."
    ciphertext = ecb.encrypt(multi_block)
    decrypted = ecb.decrypt(ciphertext)
    assert decrypted == multi_block

    print("All ECB mode tests passed!")


if __name__ == "__main__":
    test_ecb_mode()
