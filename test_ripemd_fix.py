#!/usr/bin/env python3
"""Test script to find the correct RIPEMD160 combination formula."""

import sys
sys.path.insert(0, 'src')

# Import the internal functions from ripemd160
from crypt.digest.ripemd160 import (
    _INITIAL_H, _KL, _KR, _RL, _RR, _SL, _SR, _FUNCTIONS,
    _left_rotate, _pad_message
)

def _process_block_debug(h, block):
    """Process a single 64-byte block with debug output."""
    import struct
    x = struct.unpack("<16I", block)

    al, bl, cl, dl, el = h
    ar, br, cr, dr, er = h

    # 80 rounds
    for j in range(80):
        round_num = j // 16

        # Left line
        func = _FUNCTIONS[round_num]
        temp = _left_rotate(
            (al + func(bl, cl, dl) + x[_RL[j]] + _KL[round_num]) & 0xFFFFFFFF,
            _SL[j],
        )
        al = el
        el = dl
        dl = _left_rotate(cl, 10)
        cl = bl
        bl = temp

        # Right line
        func = _FUNCTIONS[4 - round_num]
        temp = _left_rotate(
            (ar + func(br, cr, dr) + x[_RR[j]] + _KR[round_num]) & 0xFFFFFFFF,
            _SR[j],
        )
        ar = er
        er = dr
        dr = _left_rotate(cr, 10)
        cr = br
        br = temp

    print(f"After 80 rounds:")
    print(f"  Left:  al={al:08x}, bl={bl:08x}, cl={cl:08x}, dl={dl:08x}, el={el:08x}")
    print(f"  Right: ar={ar:08x}, br={br:08x}, cr={cr:08x}, dr={dr:08x}, er={er:08x}")
    print(f"  Initial h: {[f'{x:08x}' for x in h]}")

    return al, bl, cl, dl, el, ar, br, cr, dr, er


def test_combination(al, bl, cl, dl, el, ar, br, cr, dr, er, h, expected):
    """Test different combination formulas."""
    print(f"\nTesting combinations:")

    # Pattern 1: Current (direct)
    h1 = [(h[0] + al + br) & 0xFFFFFFFF,
          (h[1] + bl + cr) & 0xFFFFFFFF,
          (h[2] + cl + dr) & 0xFFFFFFFF,
          (h[3] + dl + er) & 0xFFFFFFFF,
          (h[4] + el + ar) & 0xFFFFFFFF]
    result1 = "".join(f"{word:08x}" for word in h1)
    print(f"Pattern 1 (direct): {result1} {'✓' if result1 == expected else ''}")

    # Pattern 2: With rotation (as described in summary)
    t = (h[1] + cl + dr) & 0xFFFFFFFF
    h2_1 = (h[2] + dl + er) & 0xFFFFFFFF
    h2_2 = (h[3] + el + ar) & 0xFFFFFFFF
    h2_3 = (h[4] + al + br) & 0xFFFFFFFF
    h2_4 = (h[0] + bl + cr) & 0xFFFFFFFF
    h2 = [t, h2_1, h2_2, h2_3, h2_4]
    result2 = "".join(f"{word:08x}" for word in h2)
    print(f"Pattern 2 (rotated): {result2} {'✓' if result2 == expected else ''}")

    # Pattern 3: Alternate pairing
    h3 = [(h[0] + cl + dr) & 0xFFFFFFFF,
          (h[1] + dl + er) & 0xFFFFFFFF,
          (h[2] + el + ar) & 0xFFFFFFFF,
          (h[3] + al + br) & 0xFFFFFFFF,
          (h[4] + bl + cr) & 0xFFFFFFFF]
    result3 = "".join(f"{word:08x}" for word in h3)
    print(f"Pattern 3 (alt pair): {result3} {'✓' if result3 == expected else ''}")

    # Pattern 4: Try (h[i] + left[i] + right[prev i])
    h4 = [(h[0] + al + cr) & 0xFFFFFFFF,  # al + cr instead of al + br
          (h[1] + bl + dr) & 0xFFFFFFFF,
          (h[2] + cl + er) & 0xFFFFFFFF,
          (h[3] + dl + ar) & 0xFFFFFFFF,
          (h[4] + el + br) & 0xFFFFFFFF]
    result4 = "".join(f"{word:08x}" for word in h4)
    print(f"Pattern 4 (shifted): {result4} {'✓' if result4 == expected else ''}")

    # Pattern 5: Try different pairing
    h5 = [(h[0] + al + er) & 0xFFFFFFFF,
          (h[1] + bl + ar) & 0xFFFFFFFF,
          (h[2] + cl + br) & 0xFFFFFFFF,
          (h[3] + dl + cr) & 0xFFFFFFFF,
          (h[4] + el + dr) & 0xFFFFFFFF]
    result5 = "".join(f"{word:08x}" for word in h5)
    print(f"Pattern 5 (cyclic): {result5} {'✓' if result5 == expected else ''}")


# Expected empty string hash
expected_empty = "9c1185a5c5e9fc54612808977ee8f548b2258d31"

# Create empty padded message
message = b""
original_length_bits = len(message) * 8
message = message + b"\x80"
padding_len = (56 - len(message)) % 64
message = message + b"\x00" * padding_len
message = message + b'\x00\x00\x00\x00\x00\x00\x00\x00'  # 64-bit length = 0

print(f"Padded message length: {len(message)} bytes")
print(f"Expected: {expected_empty}")

# Process the block
h = list(_INITIAL_H)
al, bl, cl, dl, el, ar, br, cr, dr, er = _process_block_debug(h, message)

# Test combinations
test_combination(al, bl, cl, dl, el, ar, br, cr, dr, er, list(_INITIAL_H), expected_empty)
