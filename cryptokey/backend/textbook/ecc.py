from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from typing import Optional, Union

from ...math import invert
from ...public import ecc

# Notation follows https://tools.ietf.org/html/rfc6979


@dataclass
class Curve:
    """
    $y^2 = x^3 + ax + b (mod p)
    """

    curve_id: ecc.CurveId

    # modulus on which curve calculations are carried out
    p: int

    # first coefficient of curve polynomial
    a: int

    # second coefficient of curve polynomial
    b: int

    # curve order
    q: int

    # Generator x coordinate
    x: InitVar[int]

    # Generator y coordinate
    y: InitVar[int]

    # Generator point
    gen: CurvePoint = field(init=False)

    def __post_init__(self, x: int, y: int) -> None:
        self.gen = CurvePoint(self.curve_id, x, y, self)


class NeutralPoint(ecc.NeutralPoint):
    def __add__(self, other: Point) -> Point:
        if not isinstance(other, (CurvePoint, NeutralPoint)):
            return NotImplemented

        return other

    def __iadd__(self, other: Point) -> Point:
        if not isinstance(other, (CurvePoint, NeutralPoint)):
            return NotImplemented

        return other

    def __mul__(self, other: int) -> NeutralPoint:
        if not isinstance(other, int):
            return NotImplemented

        return self

    def __imul__(self, other: int) -> NeutralPoint:
        if not isinstance(other, int):
            return NotImplemented

        return self

    def __rmul__(self, other: int) -> NeutralPoint:
        if not isinstance(other, int):
            return NotImplemented

        return self

    def __neg__(self) -> NeutralPoint:
        return self

    def __pos__(self) -> NeutralPoint:
        return self

    def __bool__(self) -> bool:
        return False


neutral_point = NeutralPoint()


@dataclass
class CurvePoint(ecc.CurvePoint):
    curve: Curve = field(init=False)
    _curve: InitVar[Optional[Curve]] = None

    def __post_init__(self, _curve: Optional[Curve]) -> None:
        self.curve = _curve or curve_map[self.curve_id]
        if self.y ** 2 % self.curve.p != (self.x ** 3 + self.curve.a * self.x + self.curve.b) % self.curve.p:
            raise ValueError("point not on curve")

    def __add__(self, other: Point) -> Point:
        if isinstance(other, NeutralPoint):
            return self

        if not isinstance(other, CurvePoint) or self.curve != other.curve:
            return NotImplemented

        p = self.curve.p

        if self.x == other.x and (self.y + other.y) % p == 0:
            return neutral_point

        if self == other:
            m = (3 * self.x ** 2 + self.curve.a) * invert(2 * self.y, p) % p
        else:
            m = (self.y - other.y) * invert(self.x - other.x, p) % p

        x = (m ** 2 - self.x - other.x) % p
        y = (m * (self.x - x) - self.y) % p

        return CurvePoint(self.curve_id, x, y, self.curve)

    def __mul__(self, other: int) -> Point:
        if not isinstance(other, int):
            return NotImplemented

        result = neutral_point
        tmp = self

        while other:
            if other % 2:
                result += tmp
            other >>= 1
            tmp += tmp

        return result

    def __rmul__(self, other: int) -> Point:
        if not isinstance(other, int):
            return NotImplemented

        return self * other

    def __neg__(self) -> CurvePoint:
        return CurvePoint(self.curve_id, self.x, -self.y % self.curve.p, self.curve)

    def __pos__(self) -> CurvePoint:
        return self

    def __bool__(self) -> bool:
        return True


Point = Union[NeutralPoint, CurvePoint]


NIST_P_256 = Curve(
    ecc.CurveId.NIST_P_256,
    2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1,
    -3,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

NIST_P_384 = Curve(
    ecc.CurveId.NIST_P_384,
    2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1,
    -3,
    0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
)

curve_map = {ecc.CurveId.NIST_P_256: NIST_P_256, ecc.CurveId.NIST_P_384: NIST_P_384}

# XXX compute NIST parameters from the magic seed.
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
# D.1.2.3 Curve P-256
# p    = 115792089210356248762697446949407573530086143415290314195533631308867097853951
# n    = 115792089210356248762697446949407573529996955224135760342422259061068512044369
# SEED = c49d360886e704936a6678e1139d26b7819f7e90
# c    = 7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0d
# b    = 5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
# G x  = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
# G y  = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


# https://github.com/andreacorbellini/ecc/tree/master/scripts

# XXX compute group order n using Schoof or better
