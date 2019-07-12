from __future__ import annotations
from ..hashes import HashAlgorithm


class AsymmetricPadding:
    ...


class PKCS1v15(AsymmetricPadding):
    ...


class PSS(AsymmetricPadding):
    def __init__(self, mgf: MGF1, salt_length: int) -> None:
        ...


class MGF1:
    def __init__(self, algorithm: HashAlgorithm) -> None:
        ...
