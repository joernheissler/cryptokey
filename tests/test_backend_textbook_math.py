import pytest
from cryptokey.backend.textbook import math


def test_gcdext() -> None:
    a = 15 * 8
    b = 15 * 21
    g, x, y = math.gcdext(a, b)
    assert g == a * x + b * y == 15


def test_lcm() -> None:
    assert math.lcm(15 * 8, 15 * 21) == 15 * 8 * 21


def test_invert() -> None:
    n = 15 * 21
    for i in range(1, n):
        if i % 3 and i % 5 and i % 7:
            assert math.invert(i, n) * i % n == 1
        else:
            with pytest.raises(ValueError):
                assert math.invert(i, n)
