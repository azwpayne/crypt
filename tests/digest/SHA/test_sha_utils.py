from crypt.digest.SHA.utils import (
  generate_n_sieve,
  rotate_left_64,
  sieve_of_eratosthenes,
)

import pytest


class TestRotateLeft64:
  def test_rotate_left_64_basic(self):
    assert rotate_left_64(1, 1) == 2

  def test_rotate_left_64_full_rotation_wraps(self):
    assert rotate_left_64(0x123456789ABCDEF0, 64) == 0x123456789ABCDEF0

  def test_rotate_left_64_zero_value(self):
    assert rotate_left_64(0, 32) == 0


class TestSieveOfEratosthenes:
  def test_sieve_upper_bound_less_than_2_raises(self):
    with pytest.raises(ValueError, match="must be >= 2"):
      sieve_of_eratosthenes(1)

  def test_sieve_upper_bound_exactly_2(self):
    assert sieve_of_eratosthenes(2) == [2]


class TestGenerateNSieve:
  def test_generate_n_sieve_zero(self):
    assert generate_n_sieve(0) == []

  def test_generate_n_sieve_negative(self):
    assert generate_n_sieve(-1) == []

  def test_generate_n_sieve_one(self):
    assert generate_n_sieve(1) == [2]

  def test_generate_n_sieve_five(self):
    assert generate_n_sieve(5) == [2, 3, 5, 7, 11]

  def test_generate_n_sieve_sixty_four(self):
    result = generate_n_sieve(64)
    assert len(result) == 64

  def test_generate_n_sieve_one_hundred(self):
    result = generate_n_sieve(100)
    assert len(result) == 100
