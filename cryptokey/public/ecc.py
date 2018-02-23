from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Union

# https://tools.ietf.org/html/rfc8422#appendix-A
# openssl ecparam -list_curves
# https://safecurves.cr.yp.to/

CurveId = Enum('CurveId', [
    'NIST_P_256',   # secp256r1, prime256v1
    'NIST_P_384',   # secp384r1
    'NIST_P_521',   # secp384r1
])


@dataclass
class CurvePoint:
    curve_id: CurveId
    x: int
    y: int


class NeutralPoint:
    """
    The neutral point.
    """


Point = Union[CurvePoint, NeutralPoint]
