"""Multi-dimensional verification: stdlib oracle cross-check + hypothesis property tests.

These tests validate our implementations along two complementary axes that
known-answer vectors alone do not cover:

1. **Stdlib oracle cross-check** — compare our output against authoritative
   standard-library implementations (``hashlib``, ``hmac``, ``zlib``, ``base64``).
   A match here is strong evidence of bit-correctness across arbitrary inputs,
   not just curated test vectors.

2. **Property-based tests (hypothesis)** — assert structural invariants
   (determinism, fixed output length, round-trip identity, involution) over
   generated inputs. These catch classes of bugs (e.g. a round-trip that only
   works for the vector inputs) that example-based tests miss.
"""

import base64 as stdlib_b64
import hashlib
import hmac as stdlib_hmac
import zlib
from crypt.checksum.crc.crc32 import calculate_crc32
from crypt.classical.caesar import caesar_decrypt, caesar_encrypt
from crypt.classical.rot13 import rot13
from crypt.classical.vigenere_cipher import vigenere_decrypt, vigenere_encrypt
from crypt.encode.base58 import decode_base58, encode_base58
from crypt.encode.base64 import base64_decode, base64_encode
from crypt.hash.md.md5 import md5
from crypt.hash.sha.sha1 import sha1
from crypt.hash.sha.sha2_256 import sha256
from crypt.mac.hmac.hmac_sha256 import hmac_sha256

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# =====================================================================================
# 1. Stdlib oracle cross-check  (our impl == authoritative stdlib, arbitrary inputs)
# =====================================================================================

_HASH_INPUTS = [
  pytest.param(b"", id="empty"),
  pytest.param(b"abc", id="abc"),
  pytest.param(b"Hello, World!", id="ascii"),
  pytest.param(b"The quick brown fox jumps over the lazy dog", id="pangram"),
  pytest.param(b"a" * 1000, id="long-repeat"),
  pytest.param(bytes(range(256)), id="all-bytes"),
  pytest.param(b"\x00\x00\x00", id="null-bytes"),
]


@pytest.mark.parametrize("data", _HASH_INPUTS)
def test_oracle_sha256(data):
  """Our SHA-256 hex digest must equal hashlib."""
  assert sha256(data) == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("data", _HASH_INPUTS)
def test_oracle_sha1(data):
  """Our SHA-1 hex digest must equal hashlib."""
  assert sha1(data) == hashlib.sha1(data).hexdigest()


@pytest.mark.parametrize("data", _HASH_INPUTS)
def test_oracle_md5(data):
  """Our MD5 hex digest must equal hashlib (MD5 is legacy but must be correct)."""
  assert md5(data) == hashlib.md5(data).hexdigest()


@pytest.mark.parametrize(
  "key,data",
  [
    pytest.param(b"key", b"The quick brown fox jumps over the lazy dog", id="rfc4231-1"),
    pytest.param(b"", b"", id="empty-empty"),
    pytest.param(b"secret", b"msg", id="short"),
    pytest.param(b"\x0b" * 20, b"Hi There", id="rfc4231-2"),
  ],
)
def test_oracle_hmac_sha256(key, data):
  """Our HMAC-SHA256 must equal the stdlib hmac module (raw digest bytes)."""
  assert hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()


@pytest.mark.parametrize("data", _HASH_INPUTS)
def test_oracle_crc32(data):
  """Our CRC-32 must equal zlib.crc32 across arbitrary byte inputs."""
  assert calculate_crc32(data) == zlib.crc32(data)


@pytest.mark.parametrize("data", _HASH_INPUTS)
def test_oracle_base64(data):
  """Our Base64 encode must equal stdlib base64, and decode must invert it."""
  assert base64_encode(data) == stdlib_b64.b64encode(data).decode("ascii")
  assert base64_decode(base64_encode(data)) == data


# =====================================================================================
# 2. Property-based tests (hypothesis) — structural invariants over generated input
# =====================================================================================

_FAST = settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@given(st.binary())
@_FAST
def test_property_sha256_deterministic_fixed_length_hex(data):
  h1 = sha256(data)
  h2 = sha256(data)
  assert h1 == h2  # deterministic
  assert len(h1) == 64  # 256 bits as hex
  assert int(h1, 16) >= 0  # valid hex (raises ValueError otherwise)


@given(st.binary())
@_FAST
def test_property_sha1_matches_hashlib_random(data):
  assert sha1(data) == hashlib.sha1(data).hexdigest()


@given(st.binary(min_size=0, max_size=512))
@_FAST
def test_property_base64_roundtrip(data):
  assert base64_decode(base64_encode(data)) == data


@given(st.binary(min_size=1, max_size=512))  # base58 of empty is edge-y; require >=1
@_FAST
def test_property_base58_roundtrip(data):
  assert decode_base58(encode_base58(data)) == data


# Classical ciphers: restrict to uppercase A-Z (their canonical domain).
_UPPER = st.text(alphabet=st.characters(min_codepoint=ord("A"), max_codepoint=ord("Z")), min_size=0, max_size=64)
_SHIFT = st.integers(min_value=0, max_value=25)


@given(text=_UPPER, shift=_SHIFT)
@_FAST
def test_property_caesar_roundtrip(text, shift):
  """decrypt(encrypt(x)) == x for Caesar over A-Z."""
  assert caesar_decrypt(caesar_encrypt(text, shift), shift) == text


@given(text=_UPPER)
@_FAST
def test_property_rot13_involution(text):
  """rot13 is its own inverse: rot13(rot13(x)) == x."""
  assert rot13(rot13(text)) == text


@given(text=_UPPER, key=_UPPER.filter(lambda k: len(k) > 0))
@_FAST
def test_property_vigenere_roundtrip(text, key):
  """decrypt(encrypt(x)) == x for Vigenère over A-Z with a non-empty key."""
  assert vigenere_decrypt(vigenere_encrypt(text, key), key) == text
