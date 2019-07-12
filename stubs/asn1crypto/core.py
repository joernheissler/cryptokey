from __future__ import annotations
from typing import ByteString, Union, Dict, Any, Optional, TypeVar, Type

ASN1_VALUE = TypeVar("ASN1_VALUE", bound="Asn1Value")


class Asn1Value:
    def __init__(self, value: Optional[Any] = None) -> None:
        ...

    def dump(self, force: bool = False) -> bytes:
        ...

    @classmethod
    def load(cls: Type[ASN1_VALUE], encoded_data: ByteString, strict: bool = False) -> ASN1_VALUE:
        ...

    @property
    def parsed(self) -> Any:
        ...

    @property
    def native(self) -> Any:
        ...


class ObjectIdentifier(Asn1Value):
    @property
    def dotted(self) -> str:
        ...


class Null(Asn1Value):
    ...


class Sequence(Asn1Value):
    def __getitem__(self, key: str) -> Asn1Value:
        ...


class UTF8String(Asn1Value):
    ...


class PrintableString(Asn1Value):
    ...
