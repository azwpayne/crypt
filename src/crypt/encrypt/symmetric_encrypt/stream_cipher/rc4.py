# @time    : 2026/1/6 15:53
# @name    : RC4.py
# @author  : azwpayne
# @desc    :
from Crypto.Cipher import ARC4


def rc4_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
  # 初始化 S 盒
  s_box = list(range(256))
  j = 0
  key_length = len(key)
  # 打乱 s 盒
  for i in range(256):
    j = (j + s_box[i] + key[i % key_length]) % 256
    s_box[i], s_box[j] = s_box[j], s_box[i]

  i = j = 0
  output = bytearray()

  for byte in data:
    i = (i + 1) % 256
    j = (j + s_box[i]) % 256
    s_box[i], s_box[j] = s_box[j], s_box[i]
    k = s_box[(s_box[i] + s_box[j]) % 256]
    output.append(byte ^ k)

  return bytes(output)


if __name__ == "__main__":
  plaintext = b"azwpayne"
  key = b"azwpayne"
  print(f"明文: {plaintext.hex()}")

  # 加密
  ciphertext = rc4_encrypt_decrypt(plaintext, key)
  print(f"密文: {ciphertext.hex() == ARC4.new(key).encrypt(plaintext).hex()}")

  # 解密
  decrypted_text = rc4_encrypt_decrypt(ciphertext, key)
  print(f"解密: {decrypted_text.hex() == ARC4.new(key).encrypt(ciphertext).hex()}")
