#!/usr/bin/env python3
"""Trace RIPEMD160 step by step to find the bug."""

import struct

# Initial values from the RIPEMD-160 specification
INITIAL_H = (
    0x67452301,  # A
    0xEFCDAB89,  # B  
    0x98BADCFE,  # C
    0x10325476,  # D
    0xC3D2E1F0,  # E
)

# Round constants
KL = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)

# Word selection order
RL = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)

RR = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)

# Shift amounts
SL = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)

SR = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)

# Nonlinear functions
def f1(x, y, z): return (x ^ y ^ z) & 0xFFFFFFFF
def f2(x, y, z): return ((x & y) | ((~x) & z)) & 0xFFFFFFFF
def f3(x, y, z): return ((x | (~y)) ^ z) & 0xFFFFFFFF
def f4(x, y, z): return ((x & z) | (y & (~z))) & 0xFFFFFFFF
def f5(x, y, z): return (x ^ (y | (~z))) & 0xFFFFFFFF

FUNCTIONS = (f1, f2, f3, f4, f5)

def left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

# Test with empty message
# Padding: 0x80 + zeros + 64-bit length (0)
message = b'\x80' + b'\x00' * 55 + struct.pack('<Q', 0)
print(f"Message block: {message.hex()}")
print(f"Block length: {len(message)} bytes")

# Parse block into 16 words
X = struct.unpack('<16I', message)
print(f"\nX words: {[hex(x) for x in X]}")

# Initialize working variables
A, B, C, D, E = INITIAL_H
AA, BB, CC, DD, EE = INITIAL_H

print(f"\nInitial state:")
print(f"  Left:  A={A:08x}, B={B:08x}, C={C:08x}, D={D:08x}, E={E:08x}")
print(f"  Right: AA={AA:08x}, BB={BB:08x}, CC={CC:08x}, DD={DD:08x}, EE={EE:08x}")

# Perform 80 rounds
for j in range(80):
    round_num = j // 16
    
    # Left line
    T = left_rotate((A + FUNCTIONS[round_num](B, C, D) + X[RL[j]] + KL[round_num]) & 0xFFFFFFFF, SL[j])
    A = E
    E = D
    D = left_rotate(C, 10)
    C = B
    B = T
    
    # Right line
    T = left_rotate((AA + FUNCTIONS[4 - round_num](BB, CC, DD) + X[RR[j]] + KR[round_num]) & 0xFFFFFFFF, SR[j])
    AA = EE
    EE = DD
    DD = left_rotate(CC, 10)
    CC = BB
    BB = T

print(f"\nAfter 80 rounds:")
print(f"  Left:  A={A:08x}, B={B:08x}, C={C:08x}, D={D:08x}, E={E:08x}")
print(f"  Right: AA={AA:08x}, BB={BB:08x}, CC={CC:08x}, DD={DD:08x}, EE={EE:08x}")

# Combination - according to RIPEMD-160 paper
# h[0] = h[0] + C + DD
# h[1] = h[1] + D + EE
# h[2] = h[2] + E + AA
# h[3] = h[3] + A + BB
# h[4] = h[4] + B + CC

h0 = (INITIAL_H[0] + C + DD) & 0xFFFFFFFF
h1 = (INITIAL_H[1] + D + EE) & 0xFFFFFFFF
h2 = (INITIAL_H[2] + E + AA) & 0xFFFFFFFF
h3 = (INITIAL_H[3] + A + BB) & 0xFFFFFFFF
h4 = (INITIAL_H[4] + B + CC) & 0xFFFFFFFF

result = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}"
print(f"\nCombination (paper spec):")
print(f"  h[0] = {INITIAL_H[0]:08x} + {C:08x} + {DD:08x} = {h0:08x}")
print(f"  h[1] = {INITIAL_H[1]:08x} + {D:08x} + {EE:08x} = {h1:08x}")
print(f"  h[2] = {INITIAL_H[2]:08x} + {E:08x} + {AA:08x} = {h2:08x}")
print(f"  h[3] = {INITIAL_H[3]:08x} + {A:08x} + {BB:08x} = {h3:08x}")
print(f"  h[4] = {INITIAL_H[4]:08x} + {B:08x} + {CC:08x} = {h4:08x}")
print(f"\nResult: {result}")
print(f"Expected: 9c1185a5c5e9fc54612808977ee8f548b2258d31")
print(f"Match: {result == '9c1185a5c5e9fc54612808977ee8f548b2258d31'}")
