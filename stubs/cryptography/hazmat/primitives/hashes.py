from typing import ByteString
from ..backends import Backend


class HashAlgorithm:
    @property
    def name(self) -> str:
        ...

    @property
    def digest_size(self) -> int:
        ...


class MD5(HashAlgorithm):
    ...


class SHA1(HashAlgorithm):
    ...


class SHA224(HashAlgorithm):
    ...


class SHA256(HashAlgorithm):
    ...


class SHA384(HashAlgorithm):
    ...


class SHA512(HashAlgorithm):
    ...


class BLAKE2b(HashAlgorithm):
    def __init__(self, digest_size: int) -> None:
        ...


class BLAKE2s(HashAlgorithm):
    def __init__(self, digest_size: int) -> None:
        ...


class Hash:
    def __init__(self, algorithm: HashAlgorithm, backend: Backend) -> None:
        ...

    def finalize(self) -> bytes:
        ...

    def update(self, data: ByteString) -> None:
        ...

    def copy(self) -> Hash:
        ...
