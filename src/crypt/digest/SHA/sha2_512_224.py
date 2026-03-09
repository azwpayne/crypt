# @time    : 2025/12/24 13:30
# @name    : sha2_512_224.py
# @author  : azwpayne
# @desc    :

import hashlib
import random
from string import printable

# 初始哈希值 (FIPS 180-4 第 5.3.4.2 节)
INITIAL_HASH = (
    0x8C3D37C819544DA2,
    0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82,
    0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8,
    0x77E36F7304C48942,
    0x3F9D85A86A1D36C8,
    0x1112E6AD91D692A1,
)

# 轮常数 (FIPS 180-4 第 4.2.3 节)
ROUND_CONSTANTS = (
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
)


def right_rotate(n: int, bits: int) -> int:
    """64位右循环移位"""
    return ((n >> bits) | (n << (64 - bits))) & 0xFFFFFFFFFFFFFFFF


def right_shift(n: int, bits: int) -> int:
    """64位右移"""
    return n >> bits


def ch(x: int, y: int, z: int) -> int:
    """选择函数: (x & y) ^ (~x & z)"""
    return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
    """多数函数: (x & y) ^ (x & z) ^ (y & z)"""
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x: int) -> int:
    """Σ0 函数: ROTR(28) ^ ROTR(34) ^ ROTR(39)"""
    return right_rotate(x, 28) ^ right_rotate(x, 34) ^ right_rotate(x, 39)


def sigma1(x: int) -> int:
    """Σ1 函数: ROTR(14) ^ ROTR(18) ^ ROTR(41)"""
    return right_rotate(x, 14) ^ right_rotate(x, 18) ^ right_rotate(x, 41)


def gamma0(x: int) -> int:
    """σ0 函数: ROTR(1) ^ ROTR(8) ^ SHR(7)"""
    return right_rotate(x, 1) ^ right_rotate(x, 8) ^ right_shift(x, 7)


def gamma1(x: int) -> int:
    """σ1 函数: ROTR(19) ^ ROTR(61) ^ SHR(6)"""
    return right_rotate(x, 19) ^ right_rotate(x, 61) ^ right_shift(x, 6)


def pad_message(message: bytes) -> bytes:
    """
    消息填充 (FIPS 180-4 第 5.1.1 节)
    格式: [原始消息] + 1 + [0...0] + [128位长度]
    """
    msg_len = len(message)
    bit_len = (msg_len * 8) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    # 添加1位
    padded = message + b"\x80"

    # 填充0直到长度 ≡ 112 mod 128
    while len(padded) % 128 != 112:
        padded += b"\x00"

    # 附加128位长度 (大端序)
    padded += bit_len.to_bytes(16, "big")

    return padded


def chunk_message(padded: bytes) -> tuple[tuple[int, ...], ...]:
    """
    将填充后的消息分割为 128 字节的块
    每个块转换为 16 个 64 位字 (大端序)
    """
    return tuple(
        tuple(
            int.from_bytes(padded[i + j:i + j + 8], "big")
            for j in range(0, 128, 8)
        )
        for i in range(0, len(padded), 128)
    )


# ============================================================================
# 消息调度
# ============================================================================

def message_schedule(block: tuple[int, ...]) -> tuple[int, ...]:
    """
    消息扩展 (FIPS 180-4 第 6.4.2 节)
    将16个消息字扩展为80个
    """
    w = list(block)

    for i in range(16, 80):
        s0 = gamma0(w[i - 15])
        s1 = gamma1(w[i - 2])
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF)

    return tuple(w)


# ============================================================================
# 压缩函数
# ============================================================================

# def compress_block(
#         h: Tuple[int, ...],
#         w: Tuple[int, ...],
#         k: Tuple[int, ...],
# ) -> Tuple[int, ...]:
#     """
#     块压缩函数 (FIPS 180-4 第 6.4.2 节)
#     """
#     a, b, c, d, e, f, g, h_val = h
#
#     for i in range(80):
#         # 计算 T1
#         ch_val = ch(e, f, g)
#         sigma1_val = sigma1(e)
#         t1 = (h_val + sigma1_val + ch_val + k[i] + w[i]) & 0xFFFFFFFFFFFFFFFF
#
#         # 计算 T2
#         sigma0_val = sigma0(a)
#         maj_val = maj(a, b, c)
#         t2 = (sigma0_val + maj_val) & 0xFFFFFFFFFFFFFFFF
#
#         # 更新工作变量
#         h_val = g
#         g = f
#         f = e
#         e = (d + t1) & 0xFFFFFFFFFFFFFFFF
#         d = c
#         c = b
#         b = a
#         a = (t1 + t2) & 0xFFFFFFFFFFFFFFFF
#
#     return (a, b, c, d, e, f, g, h_val)

def compress_block(
        h: tuple[int, ...],
        w: tuple[int, ...],
        k: tuple[int, ...],
) -> tuple[int, ...]:
    """
    块压缩函数 (FIPS 180-4 第 6.4.2 节)
    """
    a, b, c, d, e, f, g, h_val = h

    for i in range(80):
        # 计算 T1
        ch_val = ch(e, f, g)
        sigma1_val = sigma1(e)
        t1 = (h_val + sigma1_val + ch_val + k[i] + w[i]) & 0xFFFFFFFFFFFFFFFF

        # 计算 T2
        sigma0_val = sigma0(a)
        maj_val = maj(a, b, c)
        t2 = (sigma0_val + maj_val) & 0xFFFFFFFFFFFFFFFF

        # 同时更新工作变量，避免变量覆盖问题
        h_val, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFFFFFFFFFF, c, b, a, (
                t1 + t2) & 0xFFFFFFFFFFFFFFFF

    return a, b, c, d, e, f, g, h_val


# ============================================================================
# 主哈希函数
# ============================================================================

# def sha512_224(message: bytes) -> bytes:
#     """
#     SHA-512/224 哈希函数 (FIPS 180-4)
#
#     参数:
#         message: 输入消息字节串
#
#     返回:
#         224 位 (28 字节) 哈希值
#     """
#     # 初始化哈希值
#     h = INITIAL_HASH
#
#     # 消息预处理
#     padded = pad_message(message)
#     blocks = chunk_message(padded)
#
#     # 处理每个块
#     for block in blocks:
#         w = message_schedule(block)
#         h = compress_block(h, w, ROUND_CONSTANTS)
#
#         # 与前一哈希值相加
#         h = tuple(
#             (x + y) & 0xFFFFFFFFFFFFFFFF
#             for x, y in zip(INITIAL_HASH, h)
#         )
#
#     # 提取前224位 (7个64位字)
#     digest = b''.join(
#         word.to_bytes(8, 'big')
#         for word in h[:7]  # 7 * 64 = 448 位，但需要截断到224位
#     )
#
#     # 截断到224位 (28字节)
#     return digest[:28]

def sha512_224(message: bytes) -> bytes:
    """
    SHA-512/224 哈希函数 (FIPS 180-4)

    参数:
        message: 输入消息字节串

    返回:
        224 位 (28 字节) 哈希值
    """
    # 初始化哈希值
    h = INITIAL_HASH

    # 消息预处理
    padded = pad_message(message)
    blocks = chunk_message(padded)

    # 处理每个块
    for block in blocks:
        w = message_schedule(block)
        # 注意：这里是关键 - 压缩函数应该使用当前哈希值作为输入
        h_new = compress_block(h, w, ROUND_CONSTANTS)

        # 将压缩结果与当前哈希值相加（这是正确的）
        h = tuple(
            (current + new) & 0xFFFFFFFFFFFFFFFF
            for current, new in zip(h, h_new)
        )

    # 提取前224位 (28字节)
    full_digest = b"".join(
        word.to_bytes(8, "big")
        for word in h
    )

    # 截断到224位 (28字节)
    return full_digest[:28]


# ============================================================================
# 辅助函数
# ============================================================================

def sha512_224_hex(message: bytes) -> str:
    """返回十六进制格式的哈希值"""
    return sha512_224(message).hex()


# ============================================================================
# 测试
# ============================================================================

if __name__ == "__main__":
    for _ in range(0x10):
        example_str = "".join(random.sample(printable, random.randint(0, 0x10)))
        print(f"输入字符串: {example_str}")
        result = sha512_224_hex(example_str.encode())

        status = "✓" if result == hashlib.new("sha512_224",
                                              example_str.encode()).hexdigest() else "✗"
        print(f"输出结果: {result}")
        print(f"验证结果: {status}")

    # 测试向量来自 FIPS 180-4
    test_cases = [
        (b"", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"),
        (b"abc", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
        (b"abcd", "0c9f157ab030fb06e957c14e3938dc5908962e5dd7b66f04a36fc534"),
        (b"abcde", "880e79bb0a1d2c9b7528d851edb6b8342c58c831de98123b432a4515"),
        (b"abcdef", "236c829cfea4fd6d4de61ad15fcf34dca62342adaf9f2001c16f29b8"),
        (b"abcdefg", "4767af672b3ed107f25018dc22d6fa4b07d156e13b720971e2c4f6bf"),
        (b"abcdefgh", "792e25e0ae286d123a38950007e037d3122e76c4ee201668c385edab"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
         "fc9be3101845460350061160d05d1092d5d2eb72d62efcaa4f453bf7"),
    ]

    print("测试 SHA-512/224 实现...")
    for i, (message, expected) in enumerate(test_cases, 1):
        result = sha512_224_hex(message)
        status = "✓" if result == expected else "✗"
        print(f"测试 {i}: {status}")
        print(f"  消息: {message[:50]}")
        print(f"  期望: {expected}")
        print(f"  结果: {result}")
        print()

    # 自定义测试
    print("自定义测试:")
    custom_message = b"hello world"
    print(f"sha512_224(b'{custom_message.decode()}') = {sha512_224_hex(custom_message)}")
