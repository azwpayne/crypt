"""Classical / historical ciphers (educational only).

Pre-computational ciphers (Caesar, ROT13, Vigenère, Atbash, Affine, Polybius,
Simple Substitution, Playfair, Rail Fence). These are NOT secure and exist
only to show the historical evolution of cryptography — separated from modern
stream/block ciphers so learners are not misled about what counts as a cipher.
"""

__all__ = [
  "affine_cipher",
  "atbash_cipher",
  "caesar",
  "playfair_cipher",
  "polybius_square",
  "rail_fence_cipher",
  "rot13",
  "simple_substitution",
  "vigenere_cipher",
]

from . import (
  affine_cipher,
  atbash_cipher,
  caesar,
  playfair_cipher,
  polybius_square,
  rail_fence_cipher,
  rot13,
  simple_substitution,
  vigenere_cipher,
)
