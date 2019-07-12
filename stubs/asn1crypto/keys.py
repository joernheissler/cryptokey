from __future__ import annotations
from .core import Sequence, Asn1Value


class PrivateKeyInfo(Sequence):
    algorithm: str


class ECPointBitString(Sequence):
    @classmethod
    def from_coords(cls, x: int, y: int) -> ECPointBitString:
        ...


class NamedCurve(Sequence):
    ...


class PublicKeyInfo(Sequence):
    def wrap(private_key: Asn1Value, algorithm: str) -> PublicKeyInfo:
        ...


class RSAPublicKey(Sequence):
    ...
