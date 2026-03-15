# 古典加密算法实现

本目录包含多种古典替换密码和置换密码的纯 Python 实现。

## 算法列表

### 1. 凯撒密码 (Caesar Cipher) - `caesar_cipher.py`
- **描述**: 最简单的替换密码，通过固定偏移量替换字母
- **函数**:
  - `encrypt(text, shift)` - 加密
  - `decrypt(text, shift)` - 解密
  - `encrypt_with_custom_alphabet(text, shift, alphabet)` - 使用自定义字母表加密
  - `decrypt_with_custom_alphabet(text, shift, alphabet)` - 使用自定义字母表解密
  - `brute_force_decrypt(text, alphabet)` - 暴力破解

### 2. 仿射密码 (Affine Cipher) - `affine_cipher.py`
- **描述**: 使用线性函数 `E(x) = (ax + b) mod 26` 进行加密
- **函数**:
  - `encrypt(text, a, b)` - 加密
  - `decrypt(text, a, b)` - 解密
  - `brute_force_decrypt(text)` - 暴力破解
  - `get_valid_a_values()` - 获取有效的a值列表

### 3. 维吉尼亚密码 (Vigenère Cipher) - `vigenere_cipher.py`
- **描述**: 多表替换密码，使用密钥词进行循环移位
- **函数**:
  - `encrypt(text, key)` - 加密
  - `decrypt(text, key)` - 解密
  - `autokey_encrypt(text, key)` - 自动密钥加密
  - `autokey_decrypt(text, key)` - 自动密钥解密
  - `kasiski_examination(text)` - 卡西斯基检测
  - `friedman_test(text)` - 弗里德曼测试

### 4. 简单替换密码 (Simple Substitution) - `simple_substitution.py`
- **描述**: 任意字母替换，使用26个字母的排列作为密钥
- **函数**:
  - `encrypt(text, key)` - 加密
  - `decrypt(text, key)` - 解密
  - `generate_random_key()` - 生成随机密钥
  - `generate_key_from_keyword(keyword)` - 从关键词生成密钥
  - `frequency_analysis(text)` - 频率分析

### 5. 栅栏密码 (Rail Fence Cipher) - `rail_fence_cipher.py`
- **描述**: 置换密码，将文本按锯齿形排列后按行读取
- **函数**:
  - `encrypt(text, rails)` - 加密
  - `decrypt(text, rails)` - 解密
  - `brute_force_decrypt(text, max_rails)` - 暴力破解
  - `print_fence(text, rails)` - 可视化栅栏排列

### 6. ROT13 - `rot13.py`
- **描述**: 凯撒密码的特例，偏移量为13（自逆）
- **函数**:
  - `encrypt(text)` - 加密/解密（同一函数）
  - `decrypt(text)` - 解密/加密（同一函数）

### 7. 阿塔巴什密码 (Atbash Cipher) - `atbash_cipher.py`
- **描述**: 字母表反转替换 A↔Z, B↔Y, ...（自逆）
- **函数**:
  - `encrypt(text)` - 加密/解密
  - `decrypt(text)` - 解密/加密
  - `encrypt_hebrew(text)` - 希伯来字母表版本

### 8. 波利比奥斯方阵 (Polybius Square) - `polybius_square.py`
- **描述**: 将字母映射为坐标数字对
- **函数**:
  - `encrypt(text, key, size)` - 加密
  - `decrypt(encrypted_text, key, size)` - 解密
  - `print_square(key, size)` - 打印方阵
  - `encrypt_with_custom_output(text, key, size)` - 使用字母坐标加密

### 9. Playfair密码 - `playfair_cipher.py`
- **描述**: 双字母替换密码，使用5×5矩阵
- **函数**:
  - `encrypt(text, key)` - 加密
  - `decrypt(encrypted_text, key)` - 解密
  - `print_matrix(key)` - 打印Playfair矩阵

## 使用示例

```python
from crypt.encrypt.symmetric_encrypt.substitution import (
    caesar_encrypt, caesar_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    playfair_encrypt, playfair_decrypt
)

# 凯撒密码
cipher = caesar_encrypt("HELLO", 3)  # 'KHOOR'
plain = caesar_decrypt(cipher, 3)     # 'HELLO'

# 维吉尼亚密码
cipher = vigenere_encrypt("HELLO", "KEY")  # 'RIJVS'
plain = vigenere_decrypt(cipher, "KEY")     # 'HELLO'

# Playfair密码
cipher = playfair_encrypt("HELLO", "KEYWORD")  # 'GYIZSC'
plain = playfair_decrypt(cipher, "KEYWORD")     # 'HELXLO'
```

## 特性

- 纯 Python 实现，无外部依赖
- 类型注解支持
- 完整的文档字符串
- 支持大小写保持
- 支持非字母字符保留
- 提供密码分析工具（频率分析、暴力破解等）
