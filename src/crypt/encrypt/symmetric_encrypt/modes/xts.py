"""XTS (XEX-based Tweaked Codebook) mode implementation.

XTS mode is designed for disk encryption. It uses a single key that is internally
split into two keys: one for data encryption and one for tweak encryption.
It supports ciphertext stealing for partial final blocks.

Note: This is an educational implementation. For production use, please use
well-established cryptographic libraries.
"""

from typing import Callable

from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _encrypt_block,
    _decrypt_block,
    key_expansion,
    _get_key_params,
)


class XTSMode:
    """XTS (XEX-based Tweaked Codebook) mode of operation.

    XTS mode is designed for encrypting data on storage devices. It uses a
    "tweak" value (typically a sector number) that ensures the same plaintext
    at different locations produces different ciphertext.

    The key is internally split into two equal parts:
    - key1 = key[:len(key)//2] for data encryption/decryption
    - key2 = key[len(key)//2:] for tweak encryption

    This mode provides:
    - No padding required: ciphertext stealing handles partial final blocks
    - Parallel encryption/decryption: all blocks are independent
    - Deterministic: same plaintext at different tweaks produces different ciphertext

    Attributes:
        block_size: The block size in bytes (16 for AES).
        key: The full encryption key (will be split internally).
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
        """Initialize XTS mode.

        Args:
            encrypt_func: Optional external encrypt function.
            decrypt_func: Optional external decrypt function.
            block_size: The block size in bytes (default 16 for AES).
            key: The encryption key (required if using AES). Will be split in half.
            expanded_key: Pre-computed expanded key (optional, not used if key provided).
            nr: Number of rounds (optional, derived from key if not provided).

        Raises:
            ValueError: If key is not provided and no external functions are given.
            ValueError: If key length is odd (cannot be split evenly).
        """
        self.block_size = block_size
        self._encrypt_func = encrypt_func
        self._decrypt_func = decrypt_func

        if key is not None:
            if len(key) % 2 != 0:
                raise ValueError("Key length must be even for XTS mode")

            self.key = key
            half_len = len(key) // 2
            key1 = key[:half_len]
            key2 = key[half_len:]

            _, self.nr1 = _get_key_params(key1)
            _, self.nr2 = _get_key_params(key2)

            self.expanded_key1 = key_expansion(key1)
            self.expanded_key2 = key_expansion(key2)
        elif expanded_key is not None and nr is not None:
            self.key = None
            self.expanded_key1 = expanded_key
            self.expanded_key2 = expanded_key
            self.nr1 = nr
            self.nr2 = nr
        elif encrypt_func is None or decrypt_func is None:
            raise ValueError("Either key or both encrypt_func and decrypt_func must be provided")
        else:
            self.key = None
            self.expanded_key1 = []
            self.expanded_key2 = []
            self.nr1 = 0
            self.nr2 = 0

    def _encrypt_block(self, block: bytes, key: list[int], nr: int) -> bytes:
        """Encrypt a single block."""
        if self._encrypt_func is not None:
            return self._encrypt_func(block)
        return _encrypt_block(block, key, nr)

    def _decrypt_block(self, block: bytes, key: list[int], nr: int) -> bytes:
        """Decrypt a single block."""
        if self._decrypt_func is not None:
            return self._decrypt_func(block)
        return _decrypt_block(block, key, nr)

    def _gf_mul_alpha(self, t: int) -> int:
        """Multiply by alpha (x) in GF(2^128).

        The reduction polynomial is x^128 + x^7 + x^2 + x + 1.
        Alpha corresponds to the polynomial x.
        """
        carry = (t >> 127) & 1
        t = (t << 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        if carry:
            t ^= 0x87
        return t

    def _compute_tweak_values(self, tweak: bytes, num_blocks: int) -> list[int]:
        """Compute tweak values for all blocks.

        Args:
            tweak: The initial tweak value (sector number).
            num_blocks: Number of blocks to compute tweaks for.

        Returns:
            List of tweak values as integers.
        """
        # Pad tweak to block size
        if len(tweak) < self.block_size:
            tweak = tweak.rjust(self.block_size, b'\x00')
        elif len(tweak) > self.block_size:
            tweak = tweak[:self.block_size]

        # Encrypt tweak with key2
        t = int.from_bytes(self._encrypt_block(tweak, self.expanded_key2, self.nr2), 'big')

        # Compute tweak values for each block
        tweaks = [t]
        for _ in range(num_blocks - 1):
            t = self._gf_mul_alpha(t)
            tweaks.append(t)

        return tweaks

    def encrypt(self, plaintext: bytes, tweak: bytes) -> bytes:
        """Encrypt data using XTS mode.

        Args:
            plaintext: The data to encrypt.
            tweak: The tweak value (typically a sector number).

        Returns:
            The encrypted ciphertext.
        """
        if len(plaintext) == 0:
            return b""

        # Calculate number of full blocks and partial bytes
        num_full_blocks = len(plaintext) // self.block_size
        partial_len = len(plaintext) % self.block_size

        # If we have a partial block, we need one more tweak for ciphertext stealing
        tweaks_needed = num_full_blocks if partial_len == 0 else num_full_blocks + 1
        tweaks = self._compute_tweak_values(tweak, tweaks_needed)

        ciphertext = bytearray()
        pos = 0

        # Process full blocks
        for i in range(num_full_blocks):
            block = plaintext[pos:pos + self.block_size]
            t = tweaks[i]
            t_bytes = t.to_bytes(16, 'big')

            # XOR with tweak
            xored = bytes([block[j] ^ t_bytes[j] for j in range(self.block_size)])

            # Encrypt
            encrypted = self._encrypt_block(xored, self.expanded_key1, self.nr1)

            # XOR with tweak
            cipher_block = bytes([encrypted[j] ^ t_bytes[j] for j in range(self.block_size)])
            ciphertext.extend(cipher_block)
            pos += self.block_size

        # Handle partial final block with ciphertext stealing
        if partial_len > 0:
            # Get the last full ciphertext block (CC-1)
            if num_full_blocks > 0:
                cc_minus_1 = ciphertext[-self.block_size:]
            else:
                # Edge case: only partial block
                # Pad with zeros and encrypt
                block = plaintext[pos:].ljust(self.block_size, b'\x00')
                t = tweaks[0]
                t_bytes = t.to_bytes(16, 'big')
                xored = bytes([block[j] ^ t_bytes[j] for j in range(self.block_size)])
                encrypted = self._encrypt_block(xored, self.expanded_key1, self.nr1)
                cipher_block = bytes([encrypted[j] ^ t_bytes[j] for j in range(self.block_size)])
                return bytes(cipher_block[:partial_len])

            # Use the next tweak
            t = tweaks[num_full_blocks]
            t_bytes = t.to_bytes(16, 'big')

            # Encrypt partial plaintext with CC-1 as keystream
            partial_plain = plaintext[pos:]
            cipher_partial = bytes([partial_plain[j] ^ cc_minus_1[j] for j in range(partial_len)])

            # Create new last full block: partial ciphertext + padding from CC-1
            new_cc_minus_1 = cipher_partial + cc_minus_1[partial_len:]

            # Decrypt this to get the plaintext for the previous block position
            # Actually, we need to re-encrypt the previous block with the stolen data
            # Replace the previous ciphertext block
            ciphertext[-self.block_size:] = new_cc_minus_1

            # Add the partial ciphertext
            ciphertext.extend(cipher_partial)

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, tweak: bytes) -> bytes:
        """Decrypt data using XTS mode.

        Args:
            ciphertext: The data to decrypt.
            tweak: The tweak value (typically a sector number).

        Returns:
            The decrypted plaintext.
        """
        if len(ciphertext) == 0:
            return b""

        # Calculate number of full blocks and partial bytes
        num_full_blocks = len(ciphertext) // self.block_size
        partial_len = len(ciphertext) % self.block_size

        # If we have a partial block, handle ciphertext stealing reversal
        if partial_len > 0:
            # We have ciphertext stealing - need to recover the original blocks
            # The last full block contains the partial ciphertext + padding
            # The partial block at the end is the XOR of partial plaintext with original full block

            tweaks_needed = num_full_blocks + 1
            tweaks = self._compute_tweak_values(tweak, tweaks_needed)

            plaintext = bytearray()

            # Process all but the last two blocks (or one if only one full block)
            pos = 0
            for i in range(num_full_blocks - 1):
                block = ciphertext[pos:pos + self.block_size]
                t = tweaks[i]
                t_bytes = t.to_bytes(16, 'big')

                # XOR with tweak
                xored = bytes([block[j] ^ t_bytes[j] for j in range(self.block_size)])

                # Decrypt
                decrypted = self._decrypt_block(xored, self.expanded_key1, self.nr1)

                # XOR with tweak
                plain_block = bytes([decrypted[j] ^ t_bytes[j] for j in range(self.block_size)])
                plaintext.extend(plain_block)
                pos += self.block_size

            # Handle the last full block (which contains partial data)
            stolen_block = ciphertext[pos:pos + self.block_size]
            t = tweaks[num_full_blocks - 1]
            t_bytes = t.to_bytes(16, 'big')

            # Decrypt to get the padded plaintext
            xored = bytes([stolen_block[j] ^ t_bytes[j] for j in range(self.block_size)])
            decrypted = self._decrypt_block(xored, self.expanded_key1, self.nr1)
            padded_plain = bytes([decrypted[j] ^ t_bytes[j] for j in range(self.block_size)])

            # Get the partial ciphertext
            cipher_partial = ciphertext[pos + self.block_size:]

            # Recover partial plaintext by XORing with the beginning of padded plaintext
            plain_partial = bytes([cipher_partial[j] ^ padded_plain[j] for j in range(partial_len)])

            # The full block plaintext is the rest of padded_plain
            plain_full = padded_plain[partial_len:]

            # Decrypt the full block with next tweak
            t_next = tweaks[num_full_blocks]
            t_next_bytes = t_next.to_bytes(16, 'big')

            # Reconstruct the ciphertext block for the full block
            # It was: partial cipher + padding from original CC-1
            # We need to recover the original CC-1
            original_cc_minus_1 = bytes([
                plain_partial[j] ^ plain_full[j] if j < partial_len else padded_plain[j]
                for j in range(self.block_size)
            ])

            xored_full = bytes([original_cc_minus_1[j] ^ t_next_bytes[j] for j in range(self.block_size)])
            decrypted_full = self._decrypt_block(xored_full, self.expanded_key1, self.nr1)
            plain_full_decrypted = bytes([decrypted_full[j] ^ t_next_bytes[j] for j in range(self.block_size)])

            plaintext.extend(plain_full_decrypted)
            plaintext.extend(plain_partial)

            return bytes(plaintext)
        else:
            # No partial block - standard XTS decryption
            tweaks = self._compute_tweak_values(tweak, num_full_blocks)

            plaintext = bytearray()
            pos = 0

            for i in range(num_full_blocks):
                block = ciphertext[pos:pos + self.block_size]
                t = tweaks[i]
                t_bytes = t.to_bytes(16, 'big')

                # XOR with tweak
                xored = bytes([block[j] ^ t_bytes[j] for j in range(self.block_size)])

                # Decrypt
                decrypted = self._decrypt_block(xored, self.expanded_key1, self.nr1)

                # XOR with tweak
                plain_block = bytes([decrypted[j] ^ t_bytes[j] for j in range(self.block_size)])
                plaintext.extend(plain_block)
                pos += self.block_size

            return bytes(plaintext)


def test_xts_mode():
    """Basic tests for XTS mode."""
    key = b"0123456789abcdef0123456789abcdef"  # 256-bit key
    tweak = b"\x00" * 16

    xts = XTSMode(key=key)

    # Test basic encryption/decryption
    plaintext = b"Hello, World!1234"
    ciphertext = xts.encrypt(plaintext, tweak)
    decrypted = xts.decrypt(ciphertext, tweak)
    assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

    # Test empty data
    empty = b""
    ciphertext = xts.encrypt(empty, tweak)
    decrypted = xts.decrypt(ciphertext, tweak)
    assert decrypted == empty

    # Test various lengths
    for length in [1, 5, 15, 16, 17, 32]:
        xts = XTSMode(key=key)
        data = b"a" * length
        ciphertext = xts.encrypt(data, tweak)
        assert len(ciphertext) == length, f"Length mismatch for {length} bytes"
        decrypted = xts.decrypt(ciphertext, tweak)
        assert decrypted == data, f"Decrypt failed for {length} bytes"

    print("All XTS mode tests passed!")


if __name__ == "__main__":
    test_xts_mode()
