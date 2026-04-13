"""Pytest configuration and shared fixtures for crypt tests.

This module provides:
- Custom pytest markers for test categorization
- Shared test fixtures
- Test data generators
- Performance monitoring utilities
"""

from __future__ import annotations

import pytest


# Register custom markers
def pytest_configure(config):
  """Register custom markers."""
  config.addinivalue_line(
    "markers", "unit: marks tests as unit tests (deselect with '-m \"not unit\"')"
  )
  config.addinivalue_line("markers", "integration: marks tests as integration tests")
  config.addinivalue_line("markers", "benchmark: marks tests as performance benchmarks")
  config.addinivalue_line("markers", "load: marks tests as load/stress tests")
  config.addinivalue_line("markers", "slow: marks tests as slow-running tests")
  config.addinivalue_line("markers", "security: marks tests as security-related tests")


# Shared fixtures
@pytest.fixture
def sample_bytes():
  """Provide sample byte data for testing."""
  return b"Hello, World! This is test data."


@pytest.fixture
def binary_data():
  """Provide binary data containing all byte values."""
  return bytes(range(256))


@pytest.fixture
def large_data():
  """Provide large test data (1MB)."""
  return b"x" * (1024 * 1024)


@pytest.fixture
def test_keys():
  """Provide test keys for encryption."""
  return {
    "aes_128": b"\x00" * 16,
    "aes_192": b"\x00" * 24,
    "aes_256": b"\x00" * 32,
    "des": b"\x00" * 8,
    "des3": b"\x00" * 24,
    "blowfish": b"testkey123456789",
  }


@pytest.fixture
def test_iv():
  """Provide test IV for encryption."""
  return {
    "aes": b"\x00" * 16,
    "des": b"\x00" * 8,
  }


# Data generation utilities
def generate_random_data(size: int) -> bytes:
  """Generate random-like data of specified size.

  Note: This is deterministic for reproducible tests.
  """
  import hashlib

  chunks: list[bytes] = []
  seed = b"test_seed"
  while len(b"".join(chunks)) < size:
    seed = hashlib.sha256(seed).digest()
    chunks.append(seed)
  return b"".join(chunks)[:size]


@pytest.fixture
def data_generator():
  """Provide data generation function."""
  return generate_random_data
