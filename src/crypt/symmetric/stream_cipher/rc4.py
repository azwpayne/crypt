"""RC4 (Rivest Cipher 4) stream cipher — pure Python educational implementation.

.. warning::
    **RC4 is cryptographically broken** (statistical bias in its keystream;
    RFC 7465 forbids its use in TLS). Provided for educational comparison only
    — never use it for any real security purpose.

This module is self-contained pure Python. ``Crypto`` is imported only inside
the ``__main__`` block to cross-check output against a reference library, so
``import``-ing this module does **not** require ``pycryptodome``.
"""


def rc4_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
  """Encrypt/decrypt ``data`` with RC4 using ``key`` (symmetric stream cipher).

  RC4 uses the same function for encryption and decryption because it XORs the
  data with a keystream.

  Args:
      data: The plaintext or ciphertext bytes.
      key: The secret key bytes.

  Returns:
      The ciphertext (or recovered plaintext) bytes.
  """
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
  from Crypto.Cipher import ARC4

  plaintext = b"azwpayne"
  key = b"azwpayne"
  print(f"明文: {plaintext.hex()}")

  # 加密
  ciphertext = rc4_encrypt_decrypt(plaintext, key)
  print(f"密文匹配参考实现: {ciphertext.hex() == ARC4.new(key).encrypt(plaintext).hex()}")

  # 解密
  decrypted_text = rc4_encrypt_decrypt(ciphertext, key)
  print(f"解密匹配参考实现: {decrypted_text.hex() == ARC4.new(key).encrypt(ciphertext).hex()}")
