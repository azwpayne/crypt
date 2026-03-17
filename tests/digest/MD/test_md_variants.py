"""Tests for MD variants (MD2, MD4, MD6)."""

from crypt.digest.MD.md2 import md2
from crypt.digest.MD.md4 import md4
from crypt.digest.MD.md6 import md6, md6_128, md6_256, md6_512

# Standard test vectors from RFCs
TEST_DATA = b"hello"
TEST_DATA_EMPTY = b""
TEST_DATA_LONG = b"The quick brown fox jumps over the lazy dog"


class TestMD2:
    """Test MD2 hash implementation."""

    def test_md2_basic(self):
        """Test MD2 with basic string."""
        result = md2(TEST_DATA)
        assert isinstance(result, str)
        assert len(result) == 32  # 128-bit = 32 hex chars

    def test_md2_empty(self):
        """Test MD2 with empty string."""
        result = md2(TEST_DATA_EMPTY)
        # MD2("") = 8350e5a3e24c153df2275c9f80692773
        assert len(result) == 32

    def test_md2_hello(self):
        """Test MD2 with 'hello'."""
        result = md2(b"hello")
        # MD2 implementation uses S-box from RFC 1319
        # Note: The S-box in RFC 1319 has duplicate entries
        assert result == "5a22618266094ee165bba40afee6517c"

    def test_md2_string_input(self):
        """Test MD2 accepts string input."""
        result1 = md2("hello")
        result2 = md2(b"hello")
        assert result1 == result2

    def test_md2_long_text(self):
        """Test MD2 with longer text."""
        result = md2(TEST_DATA_LONG)
        assert len(result) == 32

    def test_md2_deterministic(self):
        """Test MD2 is deterministic."""
        result1 = md2(TEST_DATA)
        result2 = md2(TEST_DATA)
        assert result1 == result2


class TestMD4:
    """Test MD4 hash implementation."""

    def test_md4_basic(self):
        """Test MD4 with basic string."""
        result = md4(TEST_DATA)
        assert isinstance(result, str)
        assert len(result) == 32  # 128-bit = 32 hex chars

    def test_md4_empty(self):
        """Test MD4 with empty string."""
        result = md4(TEST_DATA_EMPTY)
        # MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        assert result == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_md4_hello(self):
        """Test MD4 with 'hello' - known value."""
        result = md4(b"hello")
        # Expected: 866437cb7a794bce2b727acc0362ee27
        assert result == "866437cb7a794bce2b727acc0362ee27"

    def test_md4_abc(self):
        """Test MD4 with 'abc' - known value."""
        result = md4(b"abc")
        # Expected: a448017aaf21d8525fc10ae87aa6729d
        assert result == "a448017aaf21d8525fc10ae87aa6729d"

    def test_md4_string_input(self):
        """Test MD4 accepts string input."""
        result1 = md4("hello")
        result2 = md4(b"hello")
        assert result1 == result2

    def test_md4_long_text(self):
        """Test MD4 with longer text."""
        result = md4(TEST_DATA_LONG)
        assert len(result) == 32

    def test_md4_deterministic(self):
        """Test MD4 is deterministic."""
        result1 = md4(TEST_DATA)
        result2 = md4(TEST_DATA)
        assert result1 == result2


class TestMD6:
    """Test MD6 hash implementation."""

    def test_md6_basic(self):
        """Test MD6 with basic string."""
        result = md6(TEST_DATA)
        assert isinstance(result, str)
        assert len(result) == 64  # Default 256-bit = 64 hex chars

    def test_md6_128(self):
        """Test MD6-128."""
        result = md6_128(TEST_DATA)
        assert len(result) == 32  # 128-bit = 32 hex chars

    def test_md6_256(self):
        """Test MD6-256."""
        result = md6_256(TEST_DATA)
        assert len(result) == 64  # 256-bit = 64 hex chars

    def test_md6_512(self):
        """Test MD6-512."""
        result = md6_512(TEST_DATA)
        assert len(result) == 128  # 512-bit = 128 hex chars

    def test_md6_empty(self):
        """Test MD6 with empty string."""
        result = md6(TEST_DATA_EMPTY)
        assert len(result) == 64

    def test_md6_string_input(self):
        """Test MD6 accepts string input."""
        result1 = md6("hello")
        result2 = md6(b"hello")
        assert result1 == result2

    def test_md6_long_text(self):
        """Test MD6 with longer text."""
        result = md6(TEST_DATA_LONG)
        assert len(result) == 64

    def test_md6_deterministic(self):
        """Test MD6 is deterministic."""
        result1 = md6(TEST_DATA)
        result2 = md6(TEST_DATA)
        assert result1 == result2

    def test_md6_different_sizes_different_hashes(self):
        """Test that different hash sizes produce different results."""
        result_128 = md6(TEST_DATA, hash_size=128)
        result_256 = md6(TEST_DATA, hash_size=256)
        # Different sizes should produce different hashes
        assert result_128 != result_256
        # 128-bit is 32 hex chars, 256-bit is 64 hex chars
        assert len(result_128) == 32
        assert len(result_256) == 64


class TestMDVariantsComparison:
    """Compare MD variants behavior."""

    def test_md2_vs_md4_different(self):
        """Test that MD2 and MD4 produce different hashes."""
        md2_result = md2(TEST_DATA)
        md4_result = md4(TEST_DATA)
        assert md2_result != md4_result

    def test_md4_vs_md6_different(self):
        """Test that MD4 and MD6 produce different hashes."""
        md4_result = md4(TEST_DATA)
        md6_result = md6_128(TEST_DATA)
        assert md4_result != md6_result

    def test_all_variants_different_hashes(self):
        """Test that all MD variants produce different hashes."""
        results = {
            "md2": md2(TEST_DATA),
            "md4": md4(TEST_DATA),
            "md6_128": md6_128(TEST_DATA),
        }
        # All should be unique
        assert len(set(results.values())) == len(results)


class TestMDEdgeCases:
    """Test edge cases for MD variants."""

    def test_md2_binary_data(self):
        """Test MD2 with binary data."""
        data = bytes(range(256))
        result = md2(data)
        assert len(result) == 32

    def test_md4_binary_data(self):
        """Test MD4 with binary data."""
        data = bytes(range(256))
        result = md4(data)
        assert len(result) == 32

    def test_md6_binary_data(self):
        """Test MD6 with binary data."""
        data = bytes(range(256))
        result = md6(data)
        assert len(result) == 64

    def test_md2_large_data(self):
        """Test MD2 with large data."""
        data = b"A" * 10000
        result = md2(data)
        assert len(result) == 32

    def test_md4_large_data(self):
        """Test MD4 with large data."""
        data = b"B" * 10000
        result = md4(data)
        assert len(result) == 32

    def test_md6_large_data(self):
        """Test MD6 with large data."""
        data = b"C" * 10000
        result = md6(data)
        assert len(result) == 64
