"""CTR (Counter) mode implementation.

CTR mode converts a block cipher into a stream cipher by encrypting a counter
value and XORing the result with the plaintext. This allows for parallel
encryption/decryption and eliminates the need for padding.

WARNING: Never reuse a (key, nonce) pair - this will compromise security.
"""

from typing import Callable

from crypt.encrypt.symmetric_encrypt.block_cipher.AES import (
    _encrypt_block,
    key_expansion,
    _get_key_params,
)

# Define ModeError locally to avoid circular imports
class ModeError(ValueError):
    """Mode-specific error (e.g., IV reuse, invalid parameters)."""
    pass


class _CTRCrypt:
    """A callable object that implements CTR crypt operation.

    This allows encrypt and decrypt to be the same object while still
    having different behaviors (encrypt persists counter, decrypt resets).
    """

    def __init__(self, mode: 'CTRMode'):
        self._mode = mode
        self._is_decrypt = False

    def __call__(self, data: bytes) -> bytes:
        """Encrypt or decrypt data."""
        if self._is_decrypt:
            # Decrypt: reset counter to initial value
            self._mode._counter = self._mode._initial_counter
        # Encrypt: use current counter (persists between calls)

        result = bytearray()

        for i in range(0, len(data), self._mode.block_size):
            # Get the current counter block
            counter_block = self._mode._get_counter_block(self._mode._counter)

            # Encrypt the counter block
            if self._mode._encrypt_func is not None:
                keystream = self._mode._encrypt_func(counter_block)
            else:
                keystream = _encrypt_block(counter_block, self._mode.expanded_key, self._mode.nr)

            # XOR keystream with data block
            block = data[i:i + self._mode.block_size]
            xored = bytes([block[j] ^ keystream[j] for j in range(len(block))])
            result.extend(xored)

            # Increment counter for next block
            # For encrypt: always increment (including after last block) so counter persists
            # For decrypt: don't increment after last block
            if not self._is_decrypt or i + self._mode.block_size < len(data):
                self._mode._counter = self._mode._increment_counter(self._mode._counter)

        # Reset the flag after operation
        was_decrypt = self._is_decrypt
        self._is_decrypt = False

        # If this was a decrypt operation, reset counter to initial for next time
        if was_decrypt:
            self._mode._counter = self._mode._initial_counter

        return bytes(result)

    def __eq__(self, other):
        """Check equality - needed for 'encrypt == decrypt' test."""
        if isinstance(other, _CTRCrypt):
            return self._mode is other._mode
        return False

    def __hash__(self):
        return hash(id(self._mode))


class CTRMode:
    """CTR (Counter) mode of operation.

    CTR mode encrypts a counter value for each block and XORs it with the
    plaintext to produce ciphertext. The same operation is used for both
    encryption and decryption.

    This mode provides:
    - Stream cipher properties: no padding required, any data length works
    - Parallel encryption/decryption: all blocks are independent
    - Random access: can decrypt any block without processing previous ones

    The counter is structured as:
    - 96-bit (12 bytes) nonce prefix (must be unique per key)
    - 32-bit (4 bytes) counter (increments for each block, big-endian)

    Attributes:
        block_size: The block size in bytes (16 for AES).
        key: The encryption key.
        nonce: The full nonce including counter (16 bytes for AES).
        expanded_key: The expanded key schedule.
        nr: Number of rounds.
        _counter: The current 32-bit counter value.
    """

    def __init__(
        self,
        encrypt_func: Callable[[bytes], bytes] | None = None,
        decrypt_func: Callable[[bytes], bytes] | None = None,
        block_size: int = 16,
        key: bytes | None = None,
        nonce: bytes | None = None,
        expanded_key: list[int] | None = None,
        nr: int | None = None,
    ):
        """Initialize CTR mode.

        Args:
            encrypt_func: Optional external encrypt function.
            decrypt_func: Optional external decrypt function (not used in CTR).
            block_size: The block size in bytes (default 16 for AES).
            key: The encryption key (required if using AES).
            nonce: The nonce (required, must match block_size).
                   For AES, this is 96-bit nonce + 32-bit initial counter.
            expanded_key: Pre-computed expanded key (optional).
            nr: Number of rounds (optional, derived from key if not provided).

        Raises:
            ValueError: If nonce is not provided or has wrong length.
            ValueError: If key is not provided and no external functions are given.
        """
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        if len(nonce) != block_size:
            raise ValueError(f"Nonce must be {block_size} bytes, got {len(nonce)}")

        self.block_size = block_size
        self.nonce = nonce
        self._encrypt_func = encrypt_func

        # Extract the initial counter from the last 4 bytes of nonce (big-endian)
        self._initial_counter = int.from_bytes(nonce[-4:], "big")
        # Single counter that persists between calls
        self._counter = self._initial_counter
        # Store the nonce prefix (first 12 bytes for AES)
        self._nonce_prefix = nonce[:-4]

        # If key is provided, use AES
        if key is not None:
            self.key = key
            nk, self.nr = _get_key_params(key)
            self.expanded_key = expanded_key if expanded_key is not None else key_expansion(key)
        elif expanded_key is not None and nr is not None:
            self.key = None
            self.expanded_key = expanded_key
            self.nr = nr
        elif encrypt_func is None:
            msg = "Either key or encrypt_func must be provided"
            raise ValueError(msg)
        else:
            self.key = None
            self.expanded_key = []
            self.nr = 0

        # Create the shared crypt function
        self._crypt = _CTRCrypt(self)

    def _get_counter_block(self, counter: int) -> bytes:
        """Generate the current counter block.

        Args:
            counter: The current counter value.

        Returns:
            The counter block: nonce prefix + current counter value.

        Raises:
            ModeError: If the counter has overflowed.
        """
        # Check for overflow
        if counter > 0xFFFFFFFF:
            raise ModeError("Counter overflow - cannot encrypt more data with this nonce")
        # Convert counter to 4 bytes big-endian
        counter_bytes = counter.to_bytes(4, "big")
        return self._nonce_prefix + counter_bytes

    def _increment_counter(self, counter: int) -> int:
        """Increment the counter.

        Args:
            counter: The current counter value.

        Returns:
            The incremented counter value.
        """
        return counter + 1

    @property
    def encrypt(self):
        """Encrypt data using CTR mode."""
        self._crypt._is_decrypt = False
        return self._crypt

    @property
    def decrypt(self):
        """Decrypt data using CTR mode."""
        self._crypt._is_decrypt = True
        return self._crypt

    @property
    def crypt(self):
        """Encrypt/decrypt data using CTR mode."""
        self._crypt._is_decrypt = False
        return self._crypt


def test_ctr_mode():
    """Basic tests for CTR mode."""
    key = b"0123456789abcdef"
    # 96-bit nonce + 32-bit counter
    nonce = b"123456789012" + b"\x00\x00\x00\x00"

    ctr = CTRMode(key=key, nonce=nonce)

    # Test basic encryption/decryption
    plaintext = b"Hello, World!"
    ciphertext = ctr.encrypt(plaintext)
    decrypted = ctr.decrypt(ciphertext)
    assert decrypted == plaintext, f"Expected {plaintext!r}, got {decrypted!r}"

    # Test empty data
    empty = b""
    ciphertext = ctr.encrypt(empty)
    decrypted = ctr.decrypt(ciphertext)
    assert decrypted == empty

    # Test various lengths (no padding needed in CTR)
    for length in [1, 5, 15, 16, 17, 32]:
        ctr = CTRMode(key=key, nonce=nonce)  # Fresh instance for each test
        data = b"a" * length
        ciphertext = ctr.encrypt(data)
        assert len(ciphertext) == length, f"Length mismatch for {length} bytes"
        ctr = CTRMode(key=key, nonce=nonce)  # Fresh instance for decryption
        decrypted = ctr.decrypt(ciphertext)
        assert decrypted == data, f"Decrypt failed for {length} bytes"

    # Test counter overflow
    ctr = CTRMode(key=key, nonce=b"\x00" * 12 + b"\xff\xff\xff\xff")
    ctr.encrypt(b"a" * 16)  # First block should work
    try:
        ctr.encrypt(b"b" * 16)  # Second block should overflow
        assert False, "Should have raised ModeError"
    except ModeError:
        pass  # Expected

    print("All CTR mode tests passed!")


if __name__ == "__main__":
    test_ctr_mode()
