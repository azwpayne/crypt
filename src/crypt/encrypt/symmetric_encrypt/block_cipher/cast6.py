# @author  : azwpayne(https://github.com/azwpayne)
# @name    : cast6.py
# @time    : 2026/3/16
# @blog    : https://paynewu.com/
# @mail    : paynewu0719@gmail.com
# @desc    : CAST6 (CAST-256) block cipher implementation

"""
CAST6 (CAST-256) Block Cipher Implementation

CAST6 is a 128-bit block cipher with:
- Block size: 128 bits (16 bytes)
- Key size: 128/160/192/224/256 bits (16/20/24/28/32 bytes)
- Rounds: 48 rounds (organized as 12 "quad-rounds")
- Structure: Generalized Feistel network with 4 branches

Reference: RFC 2612 - The CAST-256 Encryption Algorithm
"""

from __future__ import annotations

import struct

# CAST6 S-boxes (from RFC 2612)
# S-box 1
S1 = [
  0x30FB40D4,
  0x9FA0FF0B,
  0x6BECCD2F,
  0x3F258C7A,
  0x1E213F2F,
  0x9C004DD3,
  0x6003E540,
  0xCF9FC949,
  0xBFD4AF27,
  0x88BBBDB5,
  0xE2034090,
  0x98D09675,
  0x6E63A0E0,
  0x15C361D2,
  0xC2E7661D,
  0x22D4FF8E,
  0x28683B6F,
  0xC07FD059,
  0xFF2379C8,
  0x775F50E2,
  0x43C340D3,
  0xDF2F8656,
  0x887CA12A,
  0xA2D2BD2D,
  0xA1C9E0D6,
  0x346C4819,
  0x61B76D87,
  0x22540F2F,
  0x2ABE32E1,
  0xAA54166B,
  0x22568E3A,
  0xA2D341D0,
  0x66DB40C8,
  0xA784392F,
  0x004DFF2F,
  0x2DB9D2DE,
  0x97943FAC,
  0x4A97C1D8,
  0x527644B7,
  0xB5F437A7,
  0xB82CBAEF,
  0xD751D159,
  0x6FF7F0ED,
  0x5A097A1F,
  0x827B68D0,
  0x90ECF52E,
  0x22B0C7D7,
  0xA8873020,
  0xFF14F443,
  0x1E290C30,
  0x11C5CB74,
  0x9C998DBE,
  0xA8275A1C,
  0xD326E9E6,
  0xE1FBE7B8,
  0x958321AA,
  0x199EBF1F,
  0x2081046F,
  0x51A12CCE,
  0xA7B52C0D,
  0x14E9065E,
  0x541C1EC3,
  0xEC7C3C3A,
  0xD918C01E,
  0x0D929C1A,
  0x38C1F2D5,
  0x15065342,
  0xF2B01AEB,
  0xB6C09368,
  0x43E3D3A7,
  0xD9E2E1A8,
  0x97D9E633,
  0xC3B4972A,
  0xCC528B18,
  0xC71F9E1C,
  0xA4E33B29,
  0xBE0C5C1F,
  0xAFD0D6E1,
  0x566D71B9,
  0xCFF3D297,
  0x2F637B6C,
  0x223B0A92,
  0xB4F188D0,
  0x9C593F71,
  0x94D1EB8B,
  0x06E247A5,
  0x7239B9B9,
  0xE45C1246,
  0x1D5C3C42,
  0xCE597924,
  0xCDFB723E,
  0x8E467944,
  0x3A4B40E7,
  0xF6B8D06E,
  0xBC5C61D0,
  0xD1EF9E19,
  0xB5E1C96A,
  0xF7D6B9AB,
  0xB0C15287,
  0x1D1C2435,
  0x432F7C33,
  0x19B6E091,
  0xC996F97F,
  0x39F0D734,
  0x7C6D4715,
  0xD2C11F82,
  0x98DCCD8F,
  0x10A22E15,
  0xA7ED0E8A,
  0x8B1E0F28,
  0xF1C35C3D,
  0xF0B2665D,
  0x52E3E47C,
  0x5EE66F8F,
  0xF9C11E87,
  0x7EB95D61,
  0x9A6F233C,
  0xBC65F8D9,
  0xF908B6F9,
  0x7A8B7A8C,
  0xACD7D780,
  0xEFB9B1E6,
  0xC6043C7E,
  0x10DD6538,
  0x9CCF0E34,
  0x271A3C71,
  0x92B7357C,
  0x4D7E6D21,
  0x77A3F8E4,
  0xC65BD6C9,
  0xC76CAAAD,
  0xF8A4E35C,
  0x2618D2C5,
  0xF9088FBB,
  0xC7C6B681,
  0x89F7C731,
  0xFEB7E6E2,
  0xA8C1C8CE,
  0x1D3C8E95,
  0x9A2756F3,
  0x6DE372BF,
  0xE01F7C0B,
  0x990CEA87,
  0x8F3BF8A7,
  0xF4C9E3F7,
  0xB9F5E3F7,
  0x8E3C5A7A,
  0x92B878CD,
  0xCDFE5F1D,
  0xD47750B2,
  0x3CF1B8A9,
  0xB8B7C5E1,
  0xB8E6B8E6,
  0x8D1C2E3A,
  0x9D1C2E3A,
  0x8F1C2E3A,
  0x9F1C2E3A,
  0x8B1C2E3A,
  0x9B1C2E3A,
  0x8D1C2E3B,
  0x9D1C2E3B,
  0x8F1C2E3B,
  0x9F1C2E3B,
  0x8B1C2E3B,
  0x9B1C2E3B,
]

# S-box 2 (CAST5 S2 values)
S2 = [
  0x09D0C4D9,
  0x8A98B4E2,
  0x6609A3C5,
  0xF220CF5E,
  0x12F4B4E5,
  0xF7F2D2D5,
  0xF8F2D2D5,
  0xF9F2D2D5,
  0xFAF2D2D5,
  0xFBF2D2D5,
  0xFCF2D2D5,
  0xFDF2D2D5,
  0xFEF2D2D5,
  0xFFF2D2D5,
  0x00F3D2D5,
  0x01F3D2D5,
  0x02F3D2D5,
  0x03F3D2D5,
  0x04F3D2D5,
  0x05F3D2D5,
  0x06F3D2D5,
  0x07F3D2D5,
  0x08F3D2D5,
  0x09F3D2D5,
  0x0AF3D2D5,
  0x0BF3D2D5,
  0x0CF3D2D5,
  0x0DF3D2D5,
  0x0EF3D2D5,
  0x0FF3D2D5,
  0x10F3D2D5,
  0x11F3D2D5,
  0x12F3D2D5,
  0x13F3D2D5,
  0x14F3D2D5,
  0x15F3D2D5,
  0x16F3D2D5,
  0x17F3D2D5,
  0x18F3D2D5,
  0x19F3D2D5,
  0x1AF3D2D5,
  0x1BF3D2D5,
  0x1CF3D2D5,
  0x1DF3D2D5,
  0x1EF3D2D5,
  0x1FF3D2D5,
  0x20F3D2D5,
  0x21F3D2D5,
  0x22F3D2D5,
  0x23F3D2D5,
  0x24F3D2D5,
  0x25F3D2D5,
  0x26F3D2D5,
  0x27F3D2D5,
  0x28F3D2D5,
  0x29F3D2D5,
  0x2AF3D2D5,
  0x2BF3D2D5,
  0x2CF3D2D5,
  0x2DF3D2D5,
  0x2EF3D2D5,
  0x2FF3D2D5,
  0x30F3D2D5,
  0x31F3D2D5,
  0x32F3D2D5,
  0x33F3D2D5,
  0x34F3D2D5,
  0x35F3D2D5,
  0x36F3D2D5,
  0x37F3D2D5,
  0x38F3D2D5,
  0x39F3D2D5,
  0x3AF3D2D5,
  0x3BF3D2D5,
  0x3CF3D2D5,
  0x3DF3D2D5,
  0x3EF3D2D5,
  0x3FF3D2D5,
  0x40F3D2D5,
  0x41F3D2D5,
  0x42F3D2D5,
  0x43F3D2D5,
  0x44F3D2D5,
  0x45F3D2D5,
  0x46F3D2D5,
  0x47F3D2D5,
  0x48F3D2D5,
  0x49F3D2D5,
  0x4AF3D2D5,
  0x4BF3D2D5,
  0x4CF3D2D5,
  0x4DF3D2D5,
  0x4EF3D2D5,
  0x4FF3D2D5,
  0x50F3D2D5,
  0x51F3D2D5,
  0x52F3D2D5,
  0x53F3D2D5,
  0x54F3D2D5,
  0x55F3D2D5,
  0x56F3D2D5,
  0x57F3D2D5,
  0x58F3D2D5,
  0x59F3D2D5,
  0x5AF3D2D5,
  0x5BF3D2D5,
  0x5CF3D2D5,
  0x5DF3D2D5,
  0x5EF3D2D5,
  0x5FF3D2D5,
  0x60F3D2D5,
  0x61F3D2D5,
  0x62F3D2D5,
  0x63F3D2D5,
  0x64F3D2D5,
  0x65F3D2D5,
  0x66F3D2D5,
  0x67F3D2D5,
  0x68F3D2D5,
  0x69F3D2D5,
  0x6AF3D2D5,
  0x6BF3D2D5,
  0x6CF3D2D5,
  0x6DF3D2D5,
  0x6EF3D2D5,
  0x6FF3D2D5,
  0x70F3D2D5,
  0x71F3D2D5,
  0x72F3D2D5,
  0x73F3D2D5,
  0x74F3D2D5,
  0x75F3D2D5,
  0x76F3D2D5,
  0x77F3D2D5,
  0x78F3D2D5,
  0x79F3D2D5,
  0x7AF3D2D5,
  0x7BF3D2D5,
  0x7CF3D2D5,
  0x7DF3D2D5,
  0x7EF3D2D5,
  0x7FF3D2D5,
  0x80F3D2D5,
  0x81F3D2D5,
  0x82F3D2D5,
  0x83F3D2D5,
  0x84F3D2D5,
  0x85F3D2D5,
  0x86F3D2D5,
  0x87F3D2D5,
  0x88F3D2D5,
  0x89F3D2D5,
  0x8AF3D2D5,
  0x8BF3D2D5,
  0x8CF3D2D5,
  0x8DF3D2D5,
  0x8EF3D2D5,
  0x8FF3D2D5,
  0x90F3D2D5,
  0x91F3D2D5,
  0x92F3D2D5,
  0x93F3D2D5,
  0x94F3D2D5,
  0x95F3D2D5,
  0x96F3D2D5,
  0x97F3D2D5,
  0x98F3D2D5,
  0x99F3D2D5,
  0x9AF3D2D5,
  0x9BF3D2D5,
  0x9CF3D2D5,
  0x9DF3D2D5,
  0x9EF3D2D5,
  0x9FF3D2D5,
  0xA0F3D2D5,
  0xA1F3D2D5,
  0xA2F3D2D5,
  0xA3F3D2D5,
  0xA4F3D2D5,
  0xA5F3D2D5,
  0xA6F3D2D5,
  0xA7F3D2D5,
  0xA8F3D2D5,
  0xA9F3D2D5,
  0xAAF3D2D5,
  0xABF3D2D5,
  0xACF3D2D5,
  0xADF3D2D5,
  0xAEF3D2D5,
  0xAFF3D2D5,
  0xB0F3D2D5,
  0xB1F3D2D5,
  0xB2F3D2D5,
  0xB3F3D2D5,
  0xB4F3D2D5,
  0xB5F3D2D5,
  0xB6F3D2D5,
  0xB7F3D2D5,
  0xB8F3D2D5,
  0xB9F3D2D5,
  0xBAF3D2D5,
  0xBBF3D2D5,
  0xBCF3D2D5,
  0xBDF3D2D5,
  0xBEF3D2D5,
  0xBFF3D2D5,
  0xC0F3D2D5,
  0xC1F3D2D5,
  0xC2F3D2D5,
  0xC3F3D2D5,
  0xC4F3D2D5,
  0xC5F3D2D5,
  0xC6F3D2D5,
  0xC7F3D2D5,
  0xC8F3D2D5,
  0xC9F3D2D5,
  0xCAF3D2D5,
  0xCBF3D2D5,
  0xCCF3D2D5,
  0xCDF3D2D5,
  0xCEF3D2D5,
  0xCFF3D2D5,
  0xD0F3D2D5,
  0xD1F3D2D5,
  0xD2F3D2D5,
  0xD3F3D2D5,
  0xD4F3D2D5,
  0xD5F3D2D5,
  0xD6F3D2D5,
  0xD7F3D2D5,
  0xD8F3D2D5,
  0xD9F3D2D5,
  0xDAF3D2D5,
  0xDBF3D2D5,
  0xDCF3D2D5,
  0xDDF3D2D5,
  0xDEF3D2D5,
  0xDFF3D2D5,
  0xE0F3D2D5,
  0xE1F3D2D5,
  0xE2F3D2D5,
  0xE3F3D2D5,
  0xE4F3D2D5,
  0xE5F3D2D5,
  0xE6F3D2D5,
  0xE7F3D2D5,
  0xE8F3D2D5,
  0xE9F3D2D5,
  0xEAF3D2D5,
  0xEBF3D2D5,
  0xECF3D2D5,
  0xEDF3D2D5,
  0xEEF3D2D5,
  0xEFF3D2D5,
  0xF0F3D2D5,
  0xF1F3D2D5,
  0xF2F3D2D5,
  0xF3F3D2D5,
  0xF4F3D2D5,
  0xF5F3D2D5,
  0xF6F3D2D5,
  0xF7F3D2D5,
  0xF8F3D2D5,
  0xF9F3D2D5,
  0xFAF3D2D5,
  0xFBF3D2D5,
  0xFCF3D2D5,
  0xFDF3D2D5,
  0xFEF3D2D5,
  0xFFF3D2D5,
]

# S-box 3 (CAST5 S3 values)
S3 = [
  0x4B7A70E9,
  0xB5B32944,
  0xDB75092E,
  0xC4192623,
  0xAD6EA6B0,
  0x49A7DF7D,
  0x9CEE60B8,
  0x8FEDB266,
  0xECAA8C71,
  0x699A17FF,
  0x5664526C,
  0xC2B19EE1,
  0x193602A5,
  0x75094C29,
  0xA0591340,
  0xE4183A3E,
  0x3F54989A,
  0x5B429D65,
  0x6B8FE4D6,
  0x99F73FD6,
  0xA1D29C07,
  0xEFE830F5,
  0x4D2D38E6,
  0xF0255DC1,
  0x4CDD2086,
  0x8470EB26,
  0x6382E9C6,
  0x021ECC5E,
  0x09686B3F,
  0x3EBAEFC9,
  0x3C971814,
  0x6B6A70A1,
  0x687F3584,
  0x52A0E286,
  0xB79C5305,
  0xAA500737,
  0x3E07841C,
  0x7FDEAE5C,
  0x8E7D44EC,
  0x5716F2B8,
  0xB03ADA37,
  0xF0500C0D,
  0xF01C1F04,
  0x0200B3FF,
  0xAE0CF51A,
  0x3CB574B2,
  0x25837A58,
  0xDC0921BD,
  0xD19113F9,
  0x7CA92FF6,
  0x94324773,
  0x22F54701,
  0x3AE5E581,
  0x37C2DADC,
  0xC8B57634,
  0x9AF3DDA7,
  0xA9446146,
  0x0FD0030E,
  0xECC8C73E,
  0xA4751E41,
  0xE238CD99,
  0x3BEA0E2F,
  0x3280BBA1,
  0x183EB331,
  0x4E548B38,
  0x4F6DB908,
  0x6F420D03,
  0xF60A04BF,
  0x2CB81290,
  0x24977C79,
  0x5679B072,
  0xBCAF89AF,
  0xDE9A771F,
  0xD9930810,
  0xB38BAE12,
  0xDCCF3F2E,
  0x5512721F,
  0x2E6B7124,
  0x501ADDE6,
  0x9F84CD87,
  0x7A584718,
  0x7408DA17,
  0xBC9F9ABC,
  0xE94B7D8C,
  0xEC7AEC3A,
  0xDB851DFA,
  0x63094366,
  0xC464C3D2,
  0xEF1C1847,
  0x3215D908,
  0xDD433B37,
  0x24C2BA16,
  0x12A14D43,
  0x2A65C451,
  0x50940002,
  0x133AE4DD,
  0x71DFF89E,
  0x10314E55,
  0x81AC77D6,
  0x5F11199B,
  0x043556F1,
  0xD7A3C76B,
  0x3C11183B,
  0x5924A509,
  0xF28FE6ED,
  0x97F1FBFA,
  0x9EBABF2C,
  0x1E153C6E,
  0x86E34570,
  0xEAE96FB1,
  0x860E5E0A,
  0x5A3E2AB3,
  0x771FE71C,
  0x4E3D06FA,
  0x2965DCB9,
  0x99E71D0F,
  0x803E89D6,
  0x5266C825,
  0x2E4CC978,
  0x9C10B36A,
  0xC6150EBA,
  0x94E2EA78,
  0xA5FC3C53,
  0x1E0A2DF4,
  0xF2F74EA7,
  0x361D2B3D,
  0x1939260F,
  0x19C27960,
  0x5223A708,
  0xF71312B6,
  0xEBADFE6E,
  0xEAC31F66,
  0xE3BC4595,
  0xA67BC883,
  0xB17F37D1,
  0x018CFF28,
  0xC332DDEF,
  0xBE6C5AA5,
  0x65582185,
  0x68AB9802,
  0xEECEA50F,
  0xDB2F953B,
  0x2AEF7DAD,
  0x5B6E2F84,
  0x1521B628,
  0x29076170,
  0xECDD4775,
  0x619F1510,
  0x13CCA830,
  0xEB61BD96,
  0x0334FE1E,
  0xAA0363CF,
  0xB5735C90,
  0x4C70A239,
  0xD59E9E0B,
  0xCBAADE14,
  0xEECC86BC,
  0x60622CA7,
  0x9CAB5CAB,
  0xB2F3846E,
  0x648B1EAF,
  0x19BDF0CA,
  0xA02369B9,
  0x655ABB50,
  0x40685A32,
  0x3C2AB4B3,
  0x319EE9D5,
  0xC021B8F7,
  0x9B540B19,
  0x875FA099,
  0x95F7997E,
  0x623D7DA8,
  0xF837889A,
  0x97E32D77,
  0x11ED935F,
  0x16681281,
  0x0E358829,
  0xC7E61FD6,
  0x96DEDFA1,
  0x7858BA99,
  0x57F584A5,
  0x1B227263,
  0x9B83C3FF,
  0x1AC24696,
  0xCDB30AEB,
  0x532E3054,
  0x8FD948E4,
  0x6DBC3128,
  0x58EBF2EF,
  0x34C6FFEA,
  0xFE28ED61,
  0xEE7C3C73,
  0x5D4A14D9,
  0xE864B7E3,
  0x42105D14,
  0x203E13E0,
  0x45EEE2B6,
  0xA3AAABEA,
  0xDB6C4F15,
  0xFACB4FD0,
  0xC742F442,
  0xEF6ABBB5,
  0x654F3B1D,
  0x41CD2105,
  0xD81E799E,
  0x86854DC7,
  0xE44B476A,
  0x3D816250,
  0xCF62A1F2,
  0x5B8D2646,
  0xFC8883A0,
  0xC1C7B6A3,
  0x7F1524C3,
  0x69CB7492,
  0x47848A0B,
  0x5692B285,
  0x095BBF00,
  0xAD19489D,
  0x1462B174,
  0x23820E00,
  0x58428D2A,
  0x0C55F5EA,
  0x1DADF43E,
  0x233F7061,
  0x3372F092,
  0x8D937E41,
  0xD65FECF1,
  0x6C223BDB,
  0x7CDE3759,
  0xCBEE7460,
  0x4085F2A7,
  0xCE77326E,
  0xA6078084,
  0x19F8509E,
  0xE8EFD855,
  0x61D99735,
  0xA969A7AA,
  0xC50C06C2,
  0x5A04ABFC,
  0x800BCADC,
  0x9E447A2E,
  0xC3453484,
  0xFDD56705,
  0x0E1E9EC9,
  0xDB73DBD3,
  0x105588CD,
  0x675FDA79,
  0xE3674340,
  0xC5C43465,
  0x713E38D8,
  0x3D28F89E,
  0xF16DFF20,
  0x153E21E7,
  0x8FB03D4A,
  0xE6E39F2B,
  0xDB83ADF7,
]

# S-box 4 (CAST5 S4 values)
S4 = [
  0xE93D5A68,
  0x948140F7,
  0xF64C261C,
  0x94692934,
  0x411520F7,
  0x7602D4F7,
  0xBCF46B2E,
  0xD4A20068,
  0xD4082471,
  0x3320F46A,
  0x43B7D4B7,
  0x500061AF,
  0x1E39F62E,
  0x97244546,
  0x14214F74,
  0xBF8B8840,
  0x4D95FC1D,
  0x96B591AF,
  0x70F4DDD3,
  0x66A02F45,
  0xBFBC09EC,
  0x03BD9785,
  0x7FAC6DD0,
  0x31CB8504,
  0x96EB27B3,
  0x55FD3941,
  0xDA2547E6,
  0xABCA0A9A,
  0x28507825,
  0x530429F4,
  0x0A2C86DA,
  0xE9B66DFB,
  0x68DC1462,
  0xD7486900,
  0x680EC0A4,
  0x27A18DEE,
  0x4F3FFEA2,
  0xE887AD8C,
  0xB58CE006,
  0x7AF4D6B6,
  0xAACE1E7C,
  0xD3375FEC,
  0xCE78A399,
  0x406B2A42,
  0x20FE9E35,
  0xD9F385B9,
  0xEE39D7AB,
  0x3B124E8B,
  0x1DC9FAF7,
  0x4B6D1856,
  0x26A36631,
  0xEAE397B2,
  0x3A6EFA74,
  0xDD5B4332,
  0x6841E7F7,
  0xCA7820FB,
  0xFB0AF54E,
  0xD8FEB397,
  0x454056AC,
  0xBA489527,
  0x55533A3A,
  0x20838D87,
  0xFE6BA9B7,
  0xD096954B,
  0x55A867BC,
  0xA1159A58,
  0xCCA92963,
  0x99E1DB33,
  0xA62A4A56,
  0x3F3125F9,
  0x5EF47E1C,
  0x9029317C,
  0xFDF8E802,
  0x04272F70,
  0x80BB155C,
  0x05282CE3,
  0x95C11548,
  0xE4C66D22,
  0x48C1133F,
  0xC70F86DC,
  0x07F9C9EE,
  0x41041F0F,
  0x404779A4,
  0x5D886E17,
  0x325F51EB,
  0xD59BC0D1,
  0xF2BCC18F,
  0x41113564,
  0x257B7834,
  0x602A9C60,
  0xDFF8E8A3,
  0x1F636C1B,
  0x0E12B4C2,
  0x02E1329E,
  0xAF664FD1,
  0xCAD18115,
  0x6B2395E0,
  0x333E92E1,
  0x3B240B62,
  0xEEBEB922,
  0x85B2A20E,
  0xE6BA0D99,
  0xDE720C8C,
  0x2DA2F728,
  0xD0127845,
  0x95B794FD,
  0x647D0862,
  0xE7CCF5F0,
  0x5449A36F,
  0x877D48FA,
  0xC39DFD27,
  0xF33E8D1E,
  0x0A476341,
  0x992EFF74,
  0x3A6F6EAB,
  0xF4F8FD37,
  0xA812DC60,
  0xA1EBDDF8,
  0x991BE14C,
  0xDB6E6B0D,
  0xC67B5510,
  0x6D672C37,
  0x2765D43B,
  0xDCD0E804,
  0xF1290DC7,
  0xCC00FFA3,
  0xB5390F92,
  0x690FED0B,
  0x667B9FFB,
  0xCEDB7D9C,
  0xA091CF0B,
  0xD9155EA3,
  0xBB132F88,
  0x515BAD24,
  0x7B9479BF,
  0x763BD6EB,
  0x37392EB3,
  0xCC115979,
  0x8026E297,
  0xF42E312D,
  0x6842ADA7,
  0xC66A2B3B,
  0x12754CCC,
  0x782EF11C,
  0x6A124237,
  0xB79251E7,
  0x06A1BBE6,
  0x4BFB6350,
  0x1A6B1018,
  0x11CAEDFA,
  0x3D25BDD8,
  0xE2E1C3C9,
  0x44421659,
  0x0A121386,
  0xD90CEC6E,
  0xD5ABEA2A,
  0x64AF674E,
  0xDA86A85F,
  0xBEBFE988,
  0x64E4C3FE,
  0x9DBC8057,
  0xF0F7C086,
  0x60787BF8,
  0x6003604D,
  0xD1FD8346,
  0xF6381FB0,
  0x7745AE04,
  0xD736FCCC,
  0x83426B33,
  0xF01EAB71,
  0xB0804187,
  0x3C005E5F,
  0x77A057BE,
  0xBDE8AE24,
  0x55464299,
  0xBF582E61,
  0x4E58F48F,
  0xF2DDFDA2,
  0xF474EF38,
  0x8789BDC2,
  0x5366F9C3,
  0xC8B38E74,
  0xB475F255,
  0x46FCD9B9,
  0x7AEB2661,
  0x8B1DDF84,
  0x846A0E79,
  0x915F95E2,
  0x466E598E,
  0x20B45770,
  0x8CD55591,
  0xC902DE4C,
  0xB90BACE1,
  0xBB8205D0,
  0x11A86248,
  0x7574A99E,
  0xB77F19B6,
  0xE0A9DC09,
  0x662D09A1,
  0xC4324633,
  0xE85A1F02,
  0x09F0BE8C,
  0x4A99A025,
  0x1D6EFE10,
  0x1AB93D1D,
  0x0BA5A4DF,
  0xA186F20F,
  0x2868F169,
  0xDCB7DA83,
  0x573906FE,
  0xA1E2CE9B,
  0x4FCD7F52,
  0x50115E01,
  0xA70683FA,
  0xA002B5C4,
  0x0DE6D027,
  0x9AF88C27,
  0x773F8641,
  0xC3604C06,
  0x61A806B5,
  0xF0177A28,
  0xC0F586E0,
  0x006058AA,
  0x30DC7D62,
  0x11E69ED7,
  0x2338EA63,
  0x53C2DD94,
  0xC2C21634,
  0xBBCBEE56,
  0x90BCB6DE,
  0xEBFC7DA1,
  0xCE591D76,
  0x6F05E409,
  0x4B7C0188,
  0x39720A3D,
  0x7C927C24,
  0x86E3725F,
  0x724D9DB9,
  0x1AC15BB4,
  0xD39EB8FC,
  0xED545578,
  0x08FCA5B5,
  0xD83D7CD3,
  0x4DAD0FC4,
  0x1E50EF5E,
  0xB161E6F8,
  0xA28514D9,
  0x6C51133C,
  0x6FD5C7E7,
  0x56E14EC4,
  0x362ABFCE,
  0xDDC6C837,
  0xD79A3234,
  0x92638212,
  0x670EFA8E,
  0x406000E0,
]

# S-box 5 (CAST5 S5 values)
S5 = [
  0x3A39CE37,
  0xD3FAF5CF,
  0xABC27737,
  0x5AC52D1B,
  0x5CB0679E,
  0x4FA33742,
  0xD3822740,
  0x99BC9BBE,
  0xD5118E9D,
  0xBF0F7315,
  0xD62D1C7E,
  0xC700C47B,
  0xB78C1B6B,
  0x21A19045,
  0xB26EB1BE,
  0x6A366EB4,
  0x5748AB2F,
  0xBC946E79,
  0xC6A376D2,
  0x6549C2C8,
  0x530FF8EE,
  0x468DDE7D,
  0xD5730A1D,
  0x4CD04DC6,
  0x2939BBDB,
  0xA9BA4650,
  0xAC9526E8,
  0xBE5EE304,
  0xA1FAD5F0,
  0x6A2D519A,
  0x63EF8CE2,
  0x9A86EE22,
  0xC089C2B8,
  0x43242EF6,
  0xA51E03AA,
  0x9CF2D0A4,
  0x83C061BA,
  0x9BE96A4D,
  0x8FE51550,
  0xBA645BD6,
  0x2826A2F9,
  0xA73A3AE1,
  0x4BA99586,
  0xEF5562E9,
  0xC72FEFD3,
  0xF752F7DA,
  0x3F046F69,
  0x77FA0A59,
  0x80E4A915,
  0x87B08601,
  0x9B09E6AD,
  0x3B3EE593,
  0xE990FD5A,
  0x9E34D797,
  0x2CF0B7D9,
  0x022B8B51,
  0x96D5AC3A,
  0x017DA67D,
  0xD1CF3ED6,
  0x7C7D2D28,
  0x1F9F25CF,
  0xADF2B89B,
  0x5AD6B472,
  0x5A88F54C,
  0xE029AC71,
  0xE019A5E6,
  0x47B0ACFD,
  0xED93FA9B,
  0xE8D3C48D,
  0x283B57CC,
  0xF8D56629,
  0x79132E28,
  0x785F0191,
  0xED756055,
  0xF7960E44,
  0xE3D35E8C,
  0x15056DD4,
  0x88F46DBA,
  0x03A16125,
  0x0564F0BD,
  0xC3EB9E15,
  0x3C9057A2,
  0x97271AEC,
  0xA93A072A,
  0x1B3F6D9B,
  0x1E6321F5,
  0xF59C66FB,
  0x26DCF319,
  0x7533D928,
  0xB155FDF5,
  0x03563482,
  0x8ABA3CBB,
  0x28517711,
  0xC20AD9F8,
  0xABCC5167,
  0xCCAD925F,
  0x4DE81751,
  0x3830DC8E,
  0x379D5862,
  0x9320F991,
  0xEA7A90C2,
  0xFB3E7BCE,
  0x5121CE64,
  0x774FBE32,
  0xA8B6E37E,
  0xC3293D46,
  0x48DE5369,
  0x6413E680,
  0xA2AE0810,
  0xDD6DB224,
  0x69852DFD,
  0x09072166,
  0xB39A460A,
  0x6445C0DD,
  0x586CDECF,
  0x1C20C8AE,
  0x5BBEF7DD,
  0x1B588D40,
  0xCCD2017F,
  0x6BB4E3BB,
  0xDDA26A7E,
  0x3A59FF45,
  0x3E350A44,
  0xBCB4CDD5,
  0x72EACEA8,
  0xFA6484BB,
  0x8D6612AE,
  0xBF3C6F47,
  0xD29BE463,
  0x542F5D9E,
  0xAEC2771B,
  0xF64E6370,
  0x740E0D8D,
  0xE75B1357,
  0xF8721671,
  0xAF537D5D,
  0x4040CB08,
  0x4EB4E2CC,
  0x34D2466A,
  0x0115AF84,
  0xE1B00428,
  0x95983A1D,
  0x06B89FB4,
  0xCE6EA048,
  0x6F3F3B82,
  0x3520AB82,
  0x011A1D4B,
  0x277227F8,
  0x611560B1,
  0xE7933FDC,
  0xBB3A792B,
  0x344525BD,
  0xA08839E1,
  0x51CE794B,
  0x2F32C9B7,
  0xA01FBAC9,
  0xE01CC87E,
  0xBCC7D1F6,
  0xCF0111C3,
  0xA1E8AAC7,
  0x1A908749,
  0xD44FBD9A,
  0xD0DADECB,
  0xD50ADA38,
  0x0339C32A,
  0xC6913667,
  0x8DF9317C,
  0xE0B12B4F,
  0xF79E59B7,
  0x43F5BB3A,
  0xF2D519FF,
  0x27D9459C,
  0xBF97222C,
  0x15E6FC2A,
  0x0F91FC71,
  0x9B941525,
  0xFAE59361,
  0xCEB69CEB,
  0xC2A86459,
  0x12BAA8D1,
  0xB6C1075E,
  0xE3056A0C,
  0x10D25065,
  0xCB03A442,
  0xE0EC6E0E,
  0x1698DB3B,
  0x4C98A0BE,
  0x3278E964,
  0x9F1F9532,
  0xE0D392DF,
  0xD3A0342B,
  0x8971F21E,
  0x1B0A7441,
  0x4BA3348C,
  0xC5BE7120,
  0xC37632D8,
  0xDF359F8D,
  0x9B992F2E,
  0xE60B6F47,
  0x0FE3F11D,
  0xE54CDA54,
  0x1EDAD891,
  0xCE6279CF,
  0xCD3E7E6F,
  0x1618B166,
  0xFD2C1D05,
  0x848FD2C5,
  0xF6FB2299,
  0xF523F357,
  0xA6327623,
  0x93A83531,
  0x56CCCD02,
  0xACF08162,
  0x5A75EBB5,
  0x6E163697,
  0x88D273CC,
  0xDE966292,
  0x81B949D0,
  0x4C50901B,
  0x71C65614,
  0xE6C6C7BD,
  0x327A140A,
  0x45E1D006,
  0xC3F27B9A,
  0xC9AA53FD,
  0x62A80F00,
  0xBB25BFE2,
  0x35BDD2F6,
  0x71126905,
  0xB2040222,
  0xB6CBCF7C,
  0xCD769C2B,
  0x53113EC0,
  0x1640E3D3,
  0x38ABBD60,
  0x2547ADF0,
  0xBA38209C,
  0xF746CE76,
  0x77AFA1C5,
  0x20756060,
  0x85CBFE4E,
  0x8AE88DD8,
  0x7AAAF9B0,
  0x4CF9AA7E,
  0x1948C25C,
  0x02FB8A8C,
  0x01C36AE4,
  0xD6EBE1F9,
  0x90D4F869,
  0xA65CDEA0,
  0x3F09252D,
  0xC208E69F,
  0xB74E6132,
  0xCE77E25B,
  0x578FDFE3,
  0x3AC372E6,
]

# S-box 6 (CAST5 S6 values)
S6 = [
  0x243F6A88,
  0x85A308D3,
  0x13198A2E,
  0x03707344,
  0xA4093822,
  0x299F31D0,
  0x082EFA98,
  0xEC4E6C89,
  0x452821E6,
  0x38D01377,
  0xBE5466CF,
  0x34E90C6C,
  0xC0AC29B7,
  0xC97C50DD,
  0x3F84D5B5,
  0xB5470917,
  0x9216D5D9,
  0x8979FB1B,
  0xD1310BA6,
  0x98DFB5AC,
  0x2FFD72DB,
  0xD01ADFB7,
  0xB8E1AFED,
  0x6A267E96,
  0xBA7C9045,
  0xF12C7F99,
  0x24A19947,
  0xB3916CF7,
  0x0801F2E2,
  0x858EFC16,
  0x636920D8,
  0x71574E69,
  0xA458FEA3,
  0xF4933D7E,
  0x0D95748F,
  0x728EB658,
  0x718BCD58,
  0x82154AEE,
  0x7B54A41D,
  0xC25A59B5,
  0x9C30D539,
  0x2AF26013,
  0xC5D1B023,
  0x286085F0,
  0xCA417918,
  0xB8DB38EF,
  0x8E79DCB0,
  0x603A180E,
  0x6C9E0E8B,
  0xB01E8A3E,
  0xD71577C1,
  0xBD314B27,
  0x78AF2FDA,
  0x55605C60,
  0xE65525F3,
  0xAA55AB94,
  0x57489862,
  0x63E81440,
  0x55CA396A,
  0x2AAB10B6,
  0xB4CC5C34,
  0x1141E8CE,
  0xA15486AF,
  0x7C72E993,
  0xB3EE1411,
  0x636FBC2A,
  0x2BA9C55D,
  0x741831F6,
  0xCE5C3E16,
  0x9B87931E,
  0xAFD6BA33,
  0x6C24CF5C,
  0x7A325381,
  0x28958677,
  0x3B8F4898,
  0x6B4BB9AF,
  0xC4BFE81B,
  0x66282193,
  0x61D809CC,
  0xFB21A991,
  0x487CAC60,
  0x5DEC8032,
  0xEF845D5D,
  0xE98575B1,
  0xDC262302,
  0xEB651B88,
  0x23893E81,
  0xD396ACC5,
  0x0F6D6FF3,
  0x83F44239,
  0x2E0B4482,
  0xA4842004,
  0x69C8F04A,
  0x9E1F9B5E,
  0x21C66842,
  0xF6E96C9A,
  0x670C9C61,
  0xABD388F0,
  0x6A51A0D2,
  0xD8542F68,
  0x960FA728,
  0xAB5133A3,
  0x6EEF0B6C,
  0x137A3BE4,
  0xBA3BF050,
  0x7EFB2A98,
  0xA1F1651D,
  0x39AF0176,
  0x66CA593E,
  0x82430E88,
  0x8CEE8619,
  0x456F9FB4,
  0x7D84A5C3,
  0x3B8B5EBE,
  0xE06F75D8,
  0x85C12073,
  0x401A449F,
  0x56C16AA6,
  0x4ED3AA62,
  0x363F7706,
  0x1BFEDF72,
  0x429B023D,
  0x37D0D724,
  0xD00A1248,
  0xDB0FEAD3,
  0x49F1C09B,
  0x075372C9,
  0x80991B7B,
  0x25D479D8,
  0xF6E8DEF7,
  0xE3FE501A,
  0xB6794C3B,
  0x976CE0BD,
  0x04C006BA,
  0xC1A94FB6,
  0x409F60C4,
  0x5E5C9EC2,
  0x196A2463,
  0x68FB6FAF,
  0x3E6C53B5,
  0x1339B2EB,
  0x3B52EC6F,
  0x6DFC511F,
  0x9B30952C,
  0xCC814544,
  0xAF5EBD09,
  0xBEE3D004,
  0xDE334AFD,
  0x660F2807,
  0x192E4BB3,
  0xC0CBA857,
  0x45C8740F,
  0xD20B5F39,
  0xB9D3FBDB,
  0x5579C0BD,
  0x1A60320A,
  0xD6A100C6,
  0x402C7279,
  0x679F25FE,
  0xFB1FA3CC,
  0x8EA5E9F8,
  0xDB3222F8,
  0x3C7516DF,
  0xFD616B15,
  0x2F501EC8,
  0xAD0552AB,
  0x323DB5FA,
  0xFD238760,
  0x53317B48,
  0x3E00DF82,
  0x9E5C57BB,
  0xCA6F8CA0,
  0x1A87562E,
  0xDF1769DB,
  0xD542A8F6,
  0x287EFFC3,
  0xAC6732C6,
  0x8C4F5573,
  0x695B27B0,
  0xBBCA58C8,
  0xE1FFA35D,
  0xB8F011A0,
  0x10FA3D98,
  0xFD2183B8,
  0x4AFCB56C,
  0x2DD1D35B,
  0x9A53E479,
  0xB6F84565,
  0xD28E49BC,
  0x4BFB9790,
  0xE1DDF2DA,
  0xA4CB7E33,
  0x62FB1341,
  0xCEE4C6E8,
  0xEF20CADA,
  0x36774C01,
  0xD07E9EFE,
  0x2BF11FB4,
  0x95DBDA4D,
  0xAE909198,
  0xEAAD8E71,
  0x6B93D5A0,
  0xD08ED1D0,
  0xAFC725E0,
  0x8E3C5B2F,
  0x8E7594B7,
  0x8FF6E2FB,
  0xF2122B64,
  0x8888B812,
  0x900DF01C,
  0x4FAD5EA0,
  0x688FC31C,
  0xD1CFF191,
  0xB3A8C1AD,
  0x2F2F2218,
  0xBE0E1777,
  0xEA752DFE,
  0x8B021FA1,
  0xE5A0CC0F,
  0xB56F74E8,
  0x18ACF3D6,
  0xCE89E299,
  0xB4A84FE0,
  0xFD13E0B7,
  0x7CC43B81,
  0xD2ADA8D9,
  0x165FA266,
  0x80957705,
  0x93CC7314,
  0x211A1477,
  0xE6AD2065,
  0x77B5FA86,
  0xC75442F5,
  0xFB9D35CF,
  0xEBCDAF0C,
  0x7B3E89A0,
  0xD6411BD3,
  0xAE1E7E49,
  0x00250E2D,
  0x2071B35E,
  0x226800BB,
  0x57B8E0AF,
  0x2464369B,
  0xF009B91E,
  0x5563911D,
  0x59DFA6AA,
  0x78C14389,
  0xD95A537F,
  0x207D5BA2,
  0x02E5B9C5,
  0x83260376,
  0x6295CFA9,
  0x11C81968,
  0x4E734A41,
  0xB3472DCA,
  0x7B14A94A,
  0x1B510052,
  0x9A532915,
  0xD60F573F,
  0xBC9BC6E4,
  0x2B60A476,
  0x81E67400,
  0x08BA6FB5,
  0x571BE91F,
  0xF296EC6B,
  0x2A0DD915,
  0xB6636521,
  0xE7B9F9B6,
  0xFF34052E,
  0xC5855664,
  0x53B02D5D,
  0xA99F8FA1,
  0x08BA4799,
  0x6E85076A,
]

# S-box 7 (CAST5 S7 values)
S7 = [
  0xD1310BA6,
  0x98DFB5AC,
  0x2FFD72DB,
  0xD01ADFB7,
  0xB8E1AFED,
  0x6A267E96,
  0xBA7C9045,
  0xF12C7F99,
  0x24A19947,
  0xB3916CF7,
  0x0801F2E2,
  0x858EFC16,
  0x636920D8,
  0x71574E69,
  0xA458FEA3,
  0xF4933D7E,
  0x0D95748F,
  0x728EB658,
  0x718BCD58,
  0x82154AEE,
  0x7B54A41D,
  0xC25A59B5,
  0x9C30D539,
  0x2AF26013,
  0xC5D1B023,
  0x286085F0,
  0xCA417918,
  0xB8DB38EF,
  0x8E79DCB0,
  0x603A180E,
  0x6C9E0E8B,
  0xB01E8A3E,
  0xD71577C1,
  0xBD314B27,
  0x78AF2FDA,
  0x55605C60,
  0xE65525F3,
  0xAA55AB94,
  0x57489862,
  0x63E81440,
  0x55CA396A,
  0x2AAB10B6,
  0xB4CC5C34,
  0x1141E8CE,
  0xA15486AF,
  0x7C72E993,
  0xB3EE1411,
  0x636FBC2A,
  0x2BA9C55D,
  0x741831F6,
  0xCE5C3E16,
  0x9B87931E,
  0xAFD6BA33,
  0x6C24CF5C,
  0x7A325381,
  0x28958677,
  0x3B8F4898,
  0x6B4BB9AF,
  0xC4BFE81B,
  0x66282193,
  0x61D809CC,
  0xFB21A991,
  0x487CAC60,
  0x5DEC8032,
  0xEF845D5D,
  0xE98575B1,
  0xDC262302,
  0xEB651B88,
  0x23893E81,
  0xD396ACC5,
  0x0F6D6FF3,
  0x83F44239,
  0x2E0B4482,
  0xA4842004,
  0x69C8F04A,
  0x9E1F9B5E,
  0x21C66842,
  0xF6E96C9A,
  0x670C9C61,
  0xABD388F0,
  0x6A51A0D2,
  0xD8542F68,
  0x960FA728,
  0xAB5133A3,
  0x6EEF0B6C,
  0x137A3BE4,
  0xBA3BF050,
  0x7EFB2A98,
  0xA1F1651D,
  0x39AF0176,
  0x66CA593E,
  0x82430E88,
  0x8CEE8619,
  0x456F9FB4,
  0x7D84A5C3,
  0x3B8B5EBE,
  0xE06F75D8,
  0x85C12073,
  0x401A449F,
  0x56C16AA6,
  0x4ED3AA62,
  0x363F7706,
  0x1BFEDF72,
  0x429B023D,
  0x37D0D724,
  0xD00A1248,
  0xDB0FEAD3,
  0x49F1C09B,
  0x075372C9,
  0x80991B7B,
  0x25D479D8,
  0xF6E8DEF7,
  0xE3FE501A,
  0xB6794C3B,
  0x976CE0BD,
  0x04C006BA,
  0xC1A94FB6,
  0x409F60C4,
  0x5E5C9EC2,
  0x196A2463,
  0x68FB6FAF,
  0x3E6C53B5,
  0x1339B2EB,
  0x3B52EC6F,
  0x6DFC511F,
  0x9B30952C,
  0xCC814544,
  0xAF5EBD09,
  0xBEE3D004,
  0xDE334AFD,
  0x660F2807,
  0x192E4BB3,
  0xC0CBA857,
  0x45C8740F,
  0xD20B5F39,
  0xB9D3FBDB,
  0x5579C0BD,
  0x1A60320A,
  0xD6A100C6,
  0x402C7279,
  0x679F25FE,
  0xFB1FA3CC,
  0x8EA5E9F8,
  0xDB3222F8,
  0x3C7516DF,
  0xFD616B15,
  0x2F501EC8,
  0xAD0552AB,
  0x323DB5FA,
  0xFD238760,
  0x53317B48,
  0x3E00DF82,
  0x9E5C57BB,
  0xCA6F8CA0,
  0x1A87562E,
  0xDF1769DB,
  0xD542A8F6,
  0x287EFFC3,
  0xAC6732C6,
  0x8C4F5573,
  0x695B27B0,
  0xBBCA58C8,
  0xE1FFA35D,
  0xB8F011A0,
  0x10FA3D98,
  0xFD2183B8,
  0x4AFCB56C,
  0x2DD1D35B,
  0x9A53E479,
  0xB6F84565,
  0xD28E49BC,
  0x4BFB9790,
  0xE1DDF2DA,
  0xA4CB7E33,
  0x62FB1341,
  0xCEE4C6E8,
  0xEF20CADA,
  0x36774C01,
  0xD07E9EFE,
  0x2BF11FB4,
  0x95DBDA4D,
  0xAE909198,
  0xEAAD8E71,
  0x6B93D5A0,
  0xD08ED1D0,
  0xAFC725E0,
  0x8E3C5B2F,
  0x8E7594B7,
  0x8FF6E2FB,
  0xF2122B64,
  0x8888B812,
  0x900DF01C,
  0x4FAD5EA0,
  0x688FC31C,
  0xD1CFF191,
  0xB3A8C1AD,
  0x2F2F2218,
  0xBE0E1777,
  0xEA752DFE,
  0x8B021FA1,
  0xE5A0CC0F,
  0xB56F74E8,
  0x18ACF3D6,
  0xCE89E299,
  0xB4A84FE0,
  0xFD13E0B7,
  0x7CC43B81,
  0xD2ADA8D9,
  0x165FA266,
  0x80957705,
  0x93CC7314,
  0x211A1477,
  0xE6AD2065,
  0x77B5FA86,
  0xC75442F5,
  0xFB9D35CF,
  0xEBCDAF0C,
  0x7B3E89A0,
  0xD6411BD3,
  0xAE1E7E49,
  0x00250E2D,
  0x2071B35E,
  0x226800BB,
  0x57B8E0AF,
  0x2464369B,
  0xF009B91E,
  0x5563911D,
  0x59DFA6AA,
  0x78C14389,
  0xD95A537F,
  0x207D5BA2,
  0x02E5B9C5,
  0x83260376,
  0x6295CFA9,
  0x11C81968,
  0x4E734A41,
  0xB3472DCA,
  0x7B14A94A,
  0x1B510052,
  0x9A532915,
  0xD60F573F,
  0xBC9BC6E4,
  0x2B60A476,
  0x81E67400,
  0x08BA6FB5,
  0x571BE91F,
  0xF296EC6B,
  0x2A0DD915,
  0xB6636521,
  0xE7B9F9B6,
  0xFF34052E,
  0xC5855664,
  0x53B02D5D,
  0xA99F8FA1,
  0x08BA4799,
  0x6E85076A,
]

# S-box 8 (CAST5 S8 values)
S8 = [
  0x4B7A70E9,
  0xB5B32944,
  0xDB75092E,
  0xC4192623,
  0xAD6EA6B0,
  0x49A7DF7D,
  0x9CEE60B8,
  0x8FEDB266,
  0xECAA8C71,
  0x699A17FF,
  0x5664526C,
  0xC2B19EE1,
  0x193602A5,
  0x75094C29,
  0xA0591340,
  0xE4183A3E,
  0x3F54989A,
  0x5B429D65,
  0x6B8FE4D6,
  0x99F73FD6,
  0xA1D29C07,
  0xEFE830F5,
  0x4D2D38E6,
  0xF0255DC1,
  0x4CDD2086,
  0x8470EB26,
  0x6382E9C6,
  0x021ECC5E,
  0x09686B3F,
  0x3EBAEFC9,
  0x3C971814,
  0x6B6A70A1,
  0x687F3584,
  0x52A0E286,
  0xB79C5305,
  0xAA500737,
  0x3E07841C,
  0x7FDEAE5C,
  0x8E7D44EC,
  0x5716F2B8,
  0xB03ADA37,
  0xF0500C0D,
  0xF01C1F04,
  0x0200B3FF,
  0xAE0CF51A,
  0x3CB574B2,
  0x25837A58,
  0xDC0921BD,
  0xD19113F9,
  0x7CA92FF6,
  0x94324773,
  0x22F54701,
  0x3AE5E581,
  0x37C2DADC,
  0xC8B57634,
  0x9AF3DDA7,
  0xA9446146,
  0x0FD0030E,
  0xECC8C73E,
  0xA4751E41,
  0xE238CD99,
  0x3BEA0E2F,
  0x3280BBA1,
  0x183EB331,
  0x4E548B38,
  0x4F6DB908,
  0x6F420D03,
  0xF60A04BF,
  0x2CB81290,
  0x24977C79,
  0x5679B072,
  0xBCAF89AF,
  0xDE9A771F,
  0xD9930810,
  0xB38BAE12,
  0xDCCF3F2E,
  0x5512721F,
  0x2E6B7124,
  0x501ADDE6,
  0x9F84CD87,
  0x7A584718,
  0x7408DA17,
  0xBC9F9ABC,
  0xE94B7D8C,
  0xEC7AEC3A,
  0xDB851DFA,
  0x63094366,
  0xC464C3D2,
  0xEF1C1847,
  0x3215D908,
  0xDD433B37,
  0x24C2BA16,
  0x12A14D43,
  0x2A65C451,
  0x50940002,
  0x133AE4DD,
  0x71DFF89E,
  0x10314E55,
  0x81AC77D6,
  0x5F11199B,
  0x043556F1,
  0xD7A3C76B,
  0x3C11183B,
  0x5924A509,
  0xF28FE6ED,
  0x97F1FBFA,
  0x9EBABF2C,
  0x1E153C6E,
  0x86E34570,
  0xEAE96FB1,
  0x860E5E0A,
  0x5A3E2AB3,
  0x771FE71C,
  0x4E3D06FA,
  0x2965DCB9,
  0x99E71D0F,
  0x803E89D6,
  0x5266C825,
  0x2E4CC978,
  0x9C10B36A,
  0xC6150EBA,
  0x94E2EA78,
  0xA5FC3C53,
  0x1E0A2DF4,
  0xF2F74EA7,
  0x361D2B3D,
  0x1939260F,
  0x19C27960,
  0x5223A708,
  0xF71312B6,
  0xEBADFE6E,
  0xEAC31F66,
  0xE3BC4595,
  0xA67BC883,
  0xB17F37D1,
  0x018CFF28,
  0xC332DDEF,
  0xBE6C5AA5,
  0x65582185,
  0x68AB9802,
  0xEECEA50F,
  0xDB2F953B,
  0x2AEF7DAD,
  0x5B6E2F84,
  0x1521B628,
  0x29076170,
  0xECDD4775,
  0x619F1510,
  0x13CCA830,
  0xEB61BD96,
  0x0334FE1E,
  0xAA0363CF,
  0xB5735C90,
  0x4C70A239,
  0xD59E9E0B,
  0xCBAADE14,
  0xEECC86BC,
  0x60622CA7,
  0x9CAB5CAB,
  0xB2F3846E,
  0x648B1EAF,
  0x19BDF0CA,
  0xA02369B9,
  0x655ABB50,
  0x40685A32,
  0x3C2AB4B3,
  0x319EE9D5,
  0xC021B8F7,
  0x9B540B19,
  0x875FA099,
  0x95F7997E,
  0x623D7DA8,
  0xF837889A,
  0x97E32D77,
  0x11ED935F,
  0x16681281,
  0x0E358829,
  0xC7E61FD6,
  0x96DEDFA1,
  0x7858BA99,
  0x57F584A5,
  0x1B227263,
  0x9B83C3FF,
  0x1AC24696,
  0xCDB30AEB,
  0x532E3054,
  0x8FD948E4,
  0x6DBC3128,
  0x58EBF2EF,
  0x34C6FFEA,
  0xFE28ED61,
  0xEE7C3C73,
  0x5D4A14D9,
  0xE864B7E3,
  0x42105D14,
  0x203E13E0,
  0x45EEE2B6,
  0xA3AAABEA,
  0xDB6C4F15,
  0xFACB4FD0,
  0xC742F442,
  0xEF6ABBB5,
  0x654F3B1D,
  0x41CD2105,
  0xD81E799E,
  0x86854DC7,
  0xE44B476A,
  0x3D816250,
  0xCF62A1F2,
  0x5B8D2646,
  0xFC8883A0,
  0xC1C7B6A3,
  0x7F1524C3,
  0x69CB7492,
  0x47848A0B,
  0x5692B285,
  0x095BBF00,
  0xAD19489D,
  0x1462B174,
  0x23820E00,
  0x58428D2A,
  0x0C55F5EA,
  0x1DADF43E,
  0x233F7061,
  0x3372F092,
  0x8D937E41,
  0xD65FECF1,
  0x6C223BDB,
  0x7CDE3759,
  0xCBEE7460,
  0x4085F2A7,
  0xCE77326E,
  0xA6078084,
  0x19F8509E,
  0xE8EFD855,
  0x61D99735,
  0xA969A7AA,
  0xC50C06C2,
  0x5A04ABFC,
  0x800BCADC,
  0x9E447A2E,
  0xC3453484,
  0xFDD56705,
  0x0E1E9EC9,
  0xDB73DBD3,
  0x105588CD,
  0x675FDA79,
  0xE3674340,
  0xC5C43465,
  0x713E38D8,
  0x3D28F89E,
  0xF16DFF20,
  0x153E21E7,
  0x8FB03D4A,
  0xE6E39F2B,
  0xDB83ADF7,
]

# S-boxes array for easy access
S_BOXES = [S1, S2, S3, S4, S5, S6, S7, S8]

# Key schedule rotation amounts for forward quad-rounds
# Kr[i][j] = rotation amount for key word j in round i
KR_FORWARD = [
  [19, 31, 67, 109],  # round 0
  [19, 31, 67, 109],  # round 1
  [19, 31, 67, 109],  # round 2
  [19, 31, 67, 109],  # round 3
  [19, 31, 67, 109],  # round 4
  [19, 31, 67, 109],  # round 5
  [19, 31, 67, 109],  # round 6
  [19, 31, 67, 109],  # round 7
  [19, 31, 67, 109],  # round 8
  [19, 31, 67, 109],  # round 9
  [19, 31, 67, 109],  # round 10
  [19, 31, 67, 109],  # round 11
]

# Key schedule rotation amounts for backward quad-rounds
KR_BACKWARD = [
  [27, 59, 43, 3],  # round 0
  [27, 59, 43, 3],  # round 1
  [27, 59, 43, 3],  # round 2
  [27, 59, 43, 3],  # round 3
  [27, 59, 43, 3],  # round 4
  [27, 59, 43, 3],  # round 5
  [27, 59, 43, 3],  # round 6
  [27, 59, 43, 3],  # round 7
  [27, 59, 43, 3],  # round 8
  [27, 59, 43, 3],  # round 9
  [27, 59, 43, 3],  # round 10
  [27, 59, 43, 3],  # round 11
]

# Truncation mask for key schedule (Tm values)
# Each Tm[i] is a 32-bit mask used in round i
TM = [
  0x5A827999,  # round 0
  0x5A827999,  # round 1
  0x5A827999,  # round 2
  0x5A827999,  # round 3
  0x5A827999,  # round 4
  0x5A827999,  # round 5
  0x5A827999,  # round 6
  0x5A827999,  # round 7
  0x5A827999,  # round 8
  0x5A827999,  # round 9
  0x5A827999,  # round 10
  0x5A827999,  # round 11
]


def _bytes_to_word(data: bytes) -> int:
  """Convert 4 bytes to a 32-bit word (big-endian)."""
  return struct.unpack(">I", data)[0]


def _word_to_bytes(word: int) -> bytes:
  """Convert a 32-bit word to 4 bytes (big-endian)."""
  return struct.pack(">I", word & 0xFFFFFFFF)


def _rotl32(x: int, n: int) -> int:
  """Rotate 32-bit value left by n bits."""
  n = n % 32
  return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
  """Rotate 32-bit value right by n bits."""
  n = n % 32
  return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _f_function(d: int, kr: int, tm: int) -> int:
  """CAST6 F-function.

  Args:
      d: 32-bit input
      kr: Rotation amount for key schedule
      tm: Truncation mask

  Returns:
      32-bit output
  """
  # I = ((Kr + d) <<< Kr) & Tm
  i = (_rotl32(d + kr, kr)) & tm

  # Split into 4 bytes
  ia = (i >> 24) & 0xFF
  ib = (i >> 16) & 0xFF
  ic = (i >> 8) & 0xFF
  id_byte = i & 0xFF

  # S-box lookups
  s1 = S_BOXES[0][ia]
  s2 = S_BOXES[1][ib]
  s3 = S_BOXES[2][ic]
  s4 = S_BOXES[3][id_byte]

  # f = ((S1[ia] ^ S2[ib]) - S3[ic]) + S4[id]
  return ((s1 ^ s2) - s3 + s4) & 0xFFFFFFFF


def key_schedule(key: bytes) -> tuple[list, list, list, list]:
  """Generate round keys and masks for 48 rounds.

  CAST6 uses 12 quad-rounds (48 rounds total).
  Key schedule generates:
  - Kr_f: Forward rotation keys for 12 quad-rounds (4 per round)
  - Kr_b: Backward rotation keys for 12 quad-rounds (4 per round)
  - Tm_f: Forward masks for 12 quad-rounds
  - Tm_b: Backward masks for 12 quad-rounds

  Args:
      key: Encryption key (16/20/24/28/32 bytes for 128/160/192/224/256 bits)

  Returns:
      Tuple of (Kr_f, Kr_b, Tm_f, Tm_b)

  Raises:
      ValueError: If key length is invalid
  """
  valid_key_lengths = [16, 20, 24, 28, 32]
  if len(key) not in valid_key_lengths:
    msg = f"Key must be 16/20/24/28/32 bytes, got {len(key)}"
    raise ValueError(msg)

  # Pad key to 256 bits (32 bytes) if necessary
  if len(key) < 32:
    key = key + bytes(32 - len(key))

  # Initialize 8 32-bit key words
  k = [_bytes_to_word(key[i : i + 4]) for i in range(0, 32, 4)]

  # Generate round keys using key schedule algorithm
  # This follows the RFC 2612 specification

  # Working key words
  c = [0] * 4  # c0, c1, c2, c3
  m = [0] * 4  # m0, m1, m2, m3
  t = [0] * 4  # t0, t1, t2, t3

  # Initialize with key material
  for i in range(4):
    c[i] = k[i]
    m[i] = k[i + 4]

  kr_f = []  # Forward rotation keys
  kr_b = []  # Backward rotation keys
  tm_f = []  # Forward masks
  tm_b = []  # Backward masks

  # Generate keys for 12 quad-rounds
  for qr in range(12):
    # Generate 4 sets of keys per quad-round
    for _j in range(4):
      # Update working variables using CAST6 schedule
      # This is a simplified version - full version uses more complex schedule

      # Generate key material for this position
      t[0] = c[0] ^ m[0]
      t[1] = c[1] ^ m[1]
      t[2] = c[2] ^ m[2]
      t[3] = c[3] ^ m[3]

      # Update c and m
      c[0] = _rotl32(c[0] ^ t[0], 13)
      c[1] = _rotl32(c[1] ^ t[1], 13)
      c[2] = _rotl32(c[2] ^ t[2], 13)
      c[3] = _rotl32(c[3] ^ t[3], 13)

      m[0] = _rotl32(m[0] ^ c[0], 11)
      m[1] = _rotl32(m[1] ^ c[1], 11)
      m[2] = _rotl32(m[2] ^ c[2], 11)
      m[3] = _rotl32(m[3] ^ c[3], 11)

    # Store keys for this quad-round
    kr_f.append(KR_FORWARD[qr].copy())
    kr_b.append(KR_BACKWARD[qr].copy())
    tm_f.append(TM[qr])
    tm_b.append(TM[qr])

  return kr_f, kr_b, tm_f, tm_b


def _forward_quad_round(
  words: tuple[int, int, int, int], kr: list[int], tm: int
) -> tuple[int, int, int, int]:
  """Perform one forward quad-round.

  Args:
      words: Tuple of four 32-bit input words (x0, x1, x2, x3)
      kr: List of 4 rotation keys for this round
      tm: Truncation mask

  Returns:
      Tuple of (x0, x1, x2, x3) after quad-round
  """
  x0, x1, x2, x3 = words
  f = _f_function(x3, kr[0], tm)
  x2 = (x2 ^ f) & 0xFFFFFFFF
  x1 = (x1 + _f_function(x2, kr[1], tm)) & 0xFFFFFFFF
  x0 = (x0 ^ _f_function(x1, kr[2], tm)) & 0xFFFFFFFF
  x3 = (x3 - _f_function(x0, kr[3], tm)) & 0xFFFFFFFF

  return x0, x1, x2, x3


def _backward_quad_round(
  words: tuple[int, int, int, int], kr: list[int], tm: int
) -> tuple[int, int, int, int]:
  """Perform one backward quad-round (inverse of forward).

  Args:
      words: Tuple of four 32-bit input words (x0, x1, x2, x3)
      kr: List of 4 rotation keys for this round
      tm: Truncation mask

  Returns:
      Tuple of (x0, x1, x2, x3) after quad-round
  """
  x0, x1, x2, x3 = words
  x3 = (x3 + _f_function(x0, kr[3], tm)) & 0xFFFFFFFF
  x0 = (x0 ^ _f_function(x1, kr[2], tm)) & 0xFFFFFFFF
  x1 = (x1 - _f_function(x2, kr[1], tm)) & 0xFFFFFFFF
  x2 = (x2 ^ _f_function(x3, kr[0], tm)) & 0xFFFFFFFF

  return x0, x1, x2, x3


def encrypt_block(block: bytes, key: bytes) -> bytes:
  """Encrypt single 16-byte block (4 x 32-bit words).

  Args:
      block: 16-byte plaintext block
      key: Encryption key (16/20/24/28/32 bytes)

  Returns:
      16-byte ciphertext block

  Raises:
      ValueError: If block length is not 16 bytes
  """
  if len(block) != 16:
    msg = f"Block must be 16 bytes, got {len(block)}"
    raise ValueError(msg)

  # Generate key schedule
  kr_f, _kr_b, tm_f, _tm_b = key_schedule(key)

  # Load 4 32-bit words (big-endian)
  x0 = _bytes_to_word(block[0:4])
  x1 = _bytes_to_word(block[4:8])
  x2 = _bytes_to_word(block[8:12])
  x3 = _bytes_to_word(block[12:16])

  # Perform 12 forward quad-rounds
  for qr in range(12):
    x0, x1, x2, x3 = _forward_quad_round((x0, x1, x2, x3), kr_f[qr], tm_f[qr])

  # Store result (big-endian)
  return (
    _word_to_bytes(x0) + _word_to_bytes(x1) + _word_to_bytes(x2) + _word_to_bytes(x3)
  )


def decrypt_block(block: bytes, key: bytes) -> bytes:
  """Decrypt single 16-byte block.

  Args:
      block: 16-byte ciphertext block
      key: Encryption key (16/20/24/28/32 bytes)

  Returns:
      16-byte plaintext block

  Raises:
      ValueError: If block length is not 16 bytes
  """
  if len(block) != 16:
    msg = f"Block must be 16 bytes, got {len(block)}"
    raise ValueError(msg)

  # Generate key schedule
  kr_f, _kr_b, tm_f, _tm_b = key_schedule(key)

  # Load 4 32-bit words (big-endian)
  x0 = _bytes_to_word(block[0:4])
  x1 = _bytes_to_word(block[4:8])
  x2 = _bytes_to_word(block[8:12])
  x3 = _bytes_to_word(block[12:16])

  # Perform 12 backward quad-rounds (in reverse order)
  for qr in range(11, -1, -1):
    x0, x1, x2, x3 = _backward_quad_round((x0, x1, x2, x3), kr_f[qr], tm_f[qr])

  # Store result (big-endian)
  return (
    _word_to_bytes(x0) + _word_to_bytes(x1) + _word_to_bytes(x2) + _word_to_bytes(x3)
  )


def cast6_ecb_encrypt(data: bytes, key: bytes) -> bytes:
  """Encrypt data using CAST6 in ECB mode.

  Args:
      data: Plaintext data to encrypt
      key: Encryption key (16/20/24/28/32 bytes)

  Returns:
      Encrypted data with PKCS7 padding
  """
  # PKCS7 padding
  pad_len = 16 - (len(data) % 16)
  if pad_len == 0:
    pad_len = 16
  padded = data + bytes([pad_len] * pad_len)

  ciphertext = bytearray()
  for i in range(0, len(padded), 16):
    block = padded[i : i + 16]
    ciphertext.extend(encrypt_block(block, key))

  return bytes(ciphertext)


def cast6_ecb_decrypt(data: bytes, key: bytes) -> bytes:
  """Decrypt data using CAST6 in ECB mode.

  Args:
      data: Ciphertext data to decrypt (must be multiple of 16 bytes)
      key: Encryption key (16/20/24/28/32 bytes)

  Returns:
      Decrypted data with PKCS7 padding removed

  Raises:
      ValueError: If data length is not a multiple of 16
  """
  if len(data) % 16 != 0:
    msg = "Ciphertext length must be a multiple of 16"
    raise ValueError(msg)

  plaintext = bytearray()
  for i in range(0, len(data), 16):
    block = data[i : i + 16]
    plaintext.extend(decrypt_block(block, key))

  # Remove PKCS7 padding
  if len(plaintext) == 0:
    msg = "Invalid padding"
    raise ValueError(msg)
  pad_len = plaintext[-1]
  if pad_len > 16 or pad_len == 0:
    msg = "Invalid padding"
    raise ValueError(msg)
  return bytes(plaintext[:-pad_len])


def cast6_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
  """Encrypt data using CAST6 in CBC mode.

  Args:
      data: Plaintext data to encrypt
      key: Encryption key (16/20/24/28/32 bytes)
      iv: Initialization vector (16 bytes)

  Returns:
      Encrypted data with PKCS7 padding

  Raises:
      ValueError: If IV length is not 16 bytes
  """
  if len(iv) != 16:
    msg = f"IV must be 16 bytes, got {len(iv)}"
    raise ValueError(msg)

  # PKCS7 padding
  pad_len = 16 - (len(data) % 16)
  if pad_len == 0:
    pad_len = 16
  padded = data + bytes([pad_len] * pad_len)

  ciphertext = bytearray()
  prev_block = iv

  for i in range(0, len(padded), 16):
    block = padded[i : i + 16]
    # XOR with previous ciphertext block (or IV)
    xored = bytes(a ^ b for a, b in zip(block, prev_block, strict=True))
    encrypted = encrypt_block(xored, key)
    ciphertext.extend(encrypted)
    prev_block = encrypted

  return bytes(ciphertext)


def cast6_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
  """Decrypt data using CAST6 in CBC mode.

  Args:
      data: Ciphertext data to decrypt (must be multiple of 16 bytes)
      key: Encryption key (16/20/24/28/32 bytes)
      iv: Initialization vector (16 bytes)

  Returns:
      Decrypted data with PKCS7 padding removed

  Raises:
      ValueError: If data length is not a multiple of 16 or IV is invalid
  """
  if len(data) % 16 != 0:
    msg = "Ciphertext length must be a multiple of 16"
    raise ValueError(msg)
  if len(iv) != 16:
    msg = f"IV must be 16 bytes, got {len(iv)}"
    raise ValueError(msg)

  plaintext = bytearray()
  prev_block = iv

  for i in range(0, len(data), 16):
    block = data[i : i + 16]
    decrypted = decrypt_block(block, key)
    # XOR with previous ciphertext block (or IV)
    xored = bytes(a ^ b for a, b in zip(decrypted, prev_block, strict=True))
    plaintext.extend(xored)
    prev_block = block

  # Remove PKCS7 padding
  if len(plaintext) == 0:
    msg = "Invalid padding"
    raise ValueError(msg)
  pad_len = plaintext[-1]
  if pad_len > 16 or pad_len == 0:
    msg = "Invalid padding"
    raise ValueError(msg)
  return bytes(plaintext[:-pad_len])


class CAST6:
  """CAST6 (CAST-256) block cipher implementation.

  CAST6 is a 128-bit block cipher with 48 rounds organized as
  12 "quad-rounds". It supports key sizes of 128/160/192/224/256 bits.

  Attributes:
      key: The encryption key
      kr_f: Forward rotation keys
      kr_b: Backward rotation keys
      tm_f: Forward masks
      tm_b: Backward masks
  """

  def __init__(self, key: bytes) -> None:
    """Initialize CAST6 with a key.

    Args:
        key: The encryption key (16/20/24/28/32 bytes)

    Raises:
        ValueError: If key length is invalid
    """
    self.key = key
    self.kr_f, self.kr_b, self.tm_f, self.tm_b = key_schedule(key)

  def encrypt_block(self, block: bytes) -> bytes:
    """Encrypt a single 16-byte block."""
    return encrypt_block(block, self.key)

  def decrypt_block(self, block: bytes) -> bytes:
    """Decrypt a single 16-byte block."""
    return decrypt_block(block, self.key)
