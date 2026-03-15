# @author  : azwpayne(https://github.com/azwpayne)
# @name    : __init__.py
# @time    : 2026/3/9 08:33 Mon
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 古典替换密码和置换密码实现

from crypt.encrypt.symmetric_encrypt.substitution.affine_cipher import (
    brute_force_decrypt as affine_brute_force,
)
from crypt.encrypt.symmetric_encrypt.substitution.affine_cipher import (
    decrypt as affine_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.affine_cipher import (
    encrypt as affine_encrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.affine_cipher import (
    get_valid_a_values,
)
from crypt.encrypt.symmetric_encrypt.substitution.atbash_cipher import (
    decrypt as atbash_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.atbash_cipher import (
    encrypt as atbash_encrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.atbash_cipher import (
    encrypt_hebrew,
)
from crypt.encrypt.symmetric_encrypt.substitution.caesar_cipher import (
    brute_force_decrypt as caesar_brute_force,
)
from crypt.encrypt.symmetric_encrypt.substitution.caesar_cipher import (
    decrypt as caesar_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.caesar_cipher import (
    decrypt_with_custom_alphabet as caesar_decrypt_custom,
)
from crypt.encrypt.symmetric_encrypt.substitution.caesar_cipher import (
    encrypt as caesar_encrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.caesar_cipher import (
    encrypt_with_custom_alphabet as caesar_encrypt_custom,
)
from crypt.encrypt.symmetric_encrypt.substitution.playfair_cipher import (
    decrypt as playfair_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.playfair_cipher import (
    encrypt as playfair_encrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.playfair_cipher import (
    print_matrix as playfair_print_matrix,
)
from crypt.encrypt.symmetric_encrypt.substitution.polybius_square import (
    decrypt as polybius_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.polybius_square import (
    decrypt_with_custom_input as polybius_decrypt_custom,
)
from crypt.encrypt.symmetric_encrypt.substitution.polybius_square import (
    encrypt as polybius_encrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.polybius_square import (
    encrypt_with_custom_output as polybius_encrypt_custom,
)
from crypt.encrypt.symmetric_encrypt.substitution.polybius_square import (
    print_square as polybius_print_square,
)
from crypt.encrypt.symmetric_encrypt.substitution.rail_fence_cipher import (
    brute_force_decrypt as rail_fence_brute_force,
)
from crypt.encrypt.symmetric_encrypt.substitution.rail_fence_cipher import (
    decrypt as rail_fence_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.rail_fence_cipher import (
    encrypt as rail_fence_encrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.rail_fence_cipher import (
    print_fence,
)
from crypt.encrypt.symmetric_encrypt.substitution.rot13 import (
    decrypt as rot13_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.rot13 import (
    encrypt as rot13_encrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.simple_substitution import (
    decrypt as simple_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.simple_substitution import (
    encrypt as simple_encrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.simple_substitution import (
    frequency_analysis,
    generate_key_from_keyword,
    generate_random_key,
)
from crypt.encrypt.symmetric_encrypt.substitution.vigenere_cipher import (
    autokey_decrypt,
    autokey_encrypt,
    friedman_test,
    kasiski_examination,
)
from crypt.encrypt.symmetric_encrypt.substitution.vigenere_cipher import (
    decrypt as vigenere_decrypt,
)
from crypt.encrypt.symmetric_encrypt.substitution.vigenere_cipher import (
    encrypt as vigenere_encrypt,
)

__all__ = [
    # Affine Cipher
    "affine_brute_force",
    "affine_decrypt",
    "affine_encrypt",
    # Atbash Cipher
    "atbash_decrypt",
    "atbash_encrypt",
    # Vigenere Cipher
    "autokey_decrypt",
    "autokey_encrypt",
    # Caesar Cipher
    "caesar_brute_force",
    "caesar_decrypt",
    "caesar_decrypt_custom",
    "caesar_encrypt",
    "caesar_encrypt_custom",
    "encrypt_hebrew",
    # Simple Substitution
    "frequency_analysis",
    "friedman_test",
    "generate_key_from_keyword",
    "generate_random_key",
    "get_valid_a_values",
    "kasiski_examination",
    # Playfair Cipher
    "playfair_decrypt",
    "playfair_encrypt",
    "playfair_print_matrix",
    # Polybius Square
    "polybius_decrypt",
    "polybius_decrypt_custom",
    "polybius_encrypt",
    "polybius_encrypt_custom",
    "polybius_print_square",
    # Rail Fence Cipher
    "print_fence",
    "rail_fence_brute_force",
    "rail_fence_decrypt",
    "rail_fence_encrypt",
    # ROT13
    "rot13_decrypt",
    "rot13_encrypt",
    "simple_decrypt",
    "simple_encrypt",
    "vigenere_decrypt",
    "vigenere_encrypt",
]
