import pytest
from cryptokey.backend.textbook.ecc import NIST_P_256, NIST_P_384, CurvePoint
from cryptokey.backend.textbook.ecc import neutral_point as poi
from cryptokey.public.ecc import CurveId

point = NIST_P_256.gen * 12345


def test_neutral_add() -> None:
    with pytest.raises(TypeError):
        poi + 123
    assert poi == poi + poi


def test_neutral_iadd() -> None:
    tmp = poi
    with pytest.raises(TypeError):
        tmp += 123

    tmp += point

    assert tmp == point
    assert tmp != poi


def test_neutral_radd() -> None:
    with pytest.raises(TypeError):
        123 + poi


def test_neutral_mul() -> None:
    with pytest.raises(TypeError):
        poi * 3.14

    assert poi * 42 == poi


def test_neutral_imul() -> None:
    tmp = poi
    with pytest.raises(TypeError):
        tmp *= 3.14

    tmp *= 42
    assert tmp == poi


def test_neutral_rmul() -> None:
    with pytest.raises(TypeError):
        3.14 * poi

    assert 42 * poi == poi


def test_neutral_neg() -> None:
    assert poi == -poi


def test_neutral_pos() -> None:
    assert poi == +poi


def test_neutral_bool() -> None:
    assert not poi


def test_point_not_on_curve() -> None:
    with pytest.raises(ValueError, match="not on curve"):
        CurvePoint(CurveId.NIST_P_256, 10, 20)


def test_point_add() -> None:
    assert point + poi == point

    p384 = NIST_P_384.gen * 200
    with pytest.raises(TypeError):
        point + p384

    assert point + (-point) == poi


def test_point_mul() -> None:
    with pytest.raises(TypeError):
        point * 3.14

    assert point * NIST_P_256.q == poi


def test_point_rmul() -> None:
    with pytest.raises(TypeError):
        3.14 * point

    assert NIST_P_256.q * point == poi
    assert point * 42 == 42 * point


def test_point_neg() -> None:
    assert (-point) * 42 == -(point * 42)


def test_point_pos() -> None:
    assert +point == point


def test_point_bool() -> None:
    assert point
