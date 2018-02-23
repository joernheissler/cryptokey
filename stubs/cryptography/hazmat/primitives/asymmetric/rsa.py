from __future__ import annotations
from typing import ByteString
from ..hashes import HashAlgorithm
from ...backends import Backend
from .padding import AsymmetricPadding


class RSAPublicNumbers:
    e: int
    n: int
    def __init__(self, e: int, n: int) -> None: ...
    def public_key(self, backend: Backend) -> RSAPublicKey: ...


class RSAPublicKey:
    def public_numbers(self) -> RSAPublicNumbers: ...
    def public_bytes(self, encoding: str, format: str) -> bytes: ...

    
class RSAPrivateNumbers:
    p: int
    q: int
    d: int
    dmp1: int
    dmq1: int
    iqmp: int
    public_numbers: RSAPublicNumbers
    def __init__(self, p: int, q: int, d: int, dmp1: int, dmq1: int, iqmp: int,
                 public_numbers: RSAPublicNumbers) -> None: ...
    def private_key(self, backend: Backend) -> RSAPrivateKey: ...


class RSAPrivateKey:
    def public_key(self) -> RSAPublicKey: ...
    def private_numbers(self) -> RSAPrivateNumbers: ...
    def sign(self, data: ByteString, padding: AsymmetricPadding, algorithm: HashAlgorithm) -> bytes: ...


def rsa_crt_iqmp(p: int, q: int) -> int: ...
def rsa_crt_dmp1(private_exponent: int, p: int) -> int: ...
def rsa_crt_dmq1(private_exponent: int, q: int) -> int: ...
