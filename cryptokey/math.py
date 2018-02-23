"""
Number theoretic functions needed by crypto algorithms.
"""
# pylint: disable=invalid-name

from math import gcd
from typing import Tuple


def gcdext(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean algorithm to compute the Greatest Common Divisor.

    Return integers g, x, y such that g = ax + by = gcd(a, b)
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def lcm(a: int, b: int) -> int:
    """
    Least Common Multiple.
    """
    return a * b // gcd(a, b)


def invert(a: int, n: int) -> int:
    """
    Compute multiplicative inverse of `a` modulo `n`.

    invert(a, n) * a % n == 1
    """
    g, x, __ = gcdext(a, n)
    if g != 1:
        raise ValueError('Arguments are not coprime')
    return x % n
