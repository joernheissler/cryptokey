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
            raise ValueError('point not on curve')

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

        x = (m**2 - self.x - other.x) % p
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
    0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
)

NIST_P_384 = Curve(
    ecc.CurveId.NIST_P_384,
    2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1,
    -3,
    0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
    0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
)

curve_map = {
    ecc.CurveId.NIST_P_256: NIST_P_256,
    ecc.CurveId.NIST_P_384: NIST_P_384,
}

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
