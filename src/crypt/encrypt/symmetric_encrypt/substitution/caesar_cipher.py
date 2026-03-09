# @author  : azwpayne(https://github.com/azwpayne)
# @name    : caesar_cipher.py
# @time    : 2026/3/9 08:34 Mon
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : 凯撒密码加密和解密实现

from string import ascii_lowercase


def encrypt(text: str, shift: int) -> str:
    """
    使用凯撒密码加密文本

    参数:
        text: 待加密的字符串
        shift: 偏移量（整数）

    返回:
        加密后的字符串
    """
    result = ''
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            result += encrypted_char
        else:
            result += char
    return result


def decrypt(text: str, shift: int) -> str:
    """
    使用凯撒密码解密文本

    参数:
        text: 待解密的字符串
        shift: 偏移量（整数）

    返回:
        解密后的字符串
    """
    return encrypt(text, -shift)


def encrypt_with_custom_alphabet(
        text: str,
        shift: int,
        alphabet: str = ascii_lowercase
) -> str:
    """
    使用自定义字母表进行凯撒密码加密

    参数:
        text: 待加密的字符串
        shift: 偏移量（整数）
        alphabet: 自定义字母表 abcdefghijklmnopqrstuvwxyz

    返回:
        加密后的字符串
    """
    result = ''
    alphabet_len = len(alphabet)
    alphabet_map = {char: idx for idx, char in enumerate(alphabet)}

    for char in text:
        if char in alphabet_map:
            new_index = (alphabet_map[char] + shift) % alphabet_len
            result += alphabet[new_index]
        else:
            result += char
    return result


def decrypt_with_custom_alphabet(
        text: str,
        shift: int,
        alphabet: str = ascii_lowercase
) -> str:
    """
    使用自定义字母表进行凯撒密码解密

    参数:
        text: 待解密的字符串
        shift: 偏移量（整数）
        alphabet: 自定义字母表 abcdefghijklmnopqrstuvwxyz

    返回:
        解密后的字符串
    """
    return encrypt_with_custom_alphabet(text, -shift, alphabet)


def brute_force_decrypt(
        text: str,
        alphabet: str = ascii_lowercase
) -> dict[int, str]:
    """
    暴力破解凯撒密码，尝试所有可能的偏移量

    参数:
        text: 待解密的字符串
        alphabet: 字母表

    返回:
        包含所有可能解密结果的列表
    """
    # results = {}
    # for shift in range(0, len(alphabet)):
    #     decrypted = decrypt_with_custom_alphabet(text, shift, alphabet)
    #     # results.append(f"Shift {shift}: {decrypted}")
    #     results[shift] = decrypted
    # return results
    return {
        shift: decrypt_with_custom_alphabet(text, shift, alphabet)
        for shift in range(0, len(alphabet))
    }


if __name__ == '__main__':
    source_text = 'azwpayne'
    source_shift = 3
    print(f"Source Text: {source_text}")
    print(f"Source Shift: {source_shift}")

    # ===================
    encrypt_text = encrypt(source_text, source_shift)
    decrypt_text = decrypt(encrypt_text, source_shift)
    print(f"Encrypted Text: {encrypt_text}, Decrypted Text: {decrypt_text}")
    # =============
    encrypt_with_custom_alphabet_tex = encrypt_with_custom_alphabet(
        source_text,
        source_shift
    )
    decrypt_with_custom_alphabet_text = decrypt_with_custom_alphabet(
        encrypt_with_custom_alphabet_tex,
        source_shift
    )
    print(
        f"Encrypted Text with Custom Alphabet: {encrypt_with_custom_alphabet_tex}, "
        f"Decrypted Text with Custom Alphabet: {decrypt_with_custom_alphabet_text}"
    )

    brute_force_decrypt_text = brute_force_decrypt(encrypt_with_custom_alphabet_tex)
    print(f"brute force decrypt text: {brute_force_decrypt_text}")
