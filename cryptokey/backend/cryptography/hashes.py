from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, cast

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes as cr_hashes

from . import backend
from ... import hashes

_hash_factories: Mapping[hashes.HashAlgorithmId, Callable[[hashes.HashParameters], cr_hashes.HashAlgorithm]] = {
    hashes.HashAlgorithmId.MD5: lambda params: cr_hashes.MD5(),
    hashes.HashAlgorithmId.SHA1: lambda params: cr_hashes.SHA1(),
    hashes.HashAlgorithmId.SHA2_224: lambda params: cr_hashes.SHA224(),
    hashes.HashAlgorithmId.SHA2_256: lambda params: cr_hashes.SHA256(),
    hashes.HashAlgorithmId.SHA2_384: lambda params: cr_hashes.SHA384(),
    hashes.HashAlgorithmId.SHA2_512: lambda params: cr_hashes.SHA512(),
    hashes.HashAlgorithmId.BLAKE2B: lambda params: cr_hashes.BLAKE2b(cast(hashes.Blake2Params, params).length),
    hashes.HashAlgorithmId.BLAKE2S: lambda params: cr_hashes.BLAKE2s(cast(hashes.Blake2Params, params).length),
}


def create_hash(hash_alg: hashes.HashAlgorithm) -> cr_hashes.HashAlgorithm:
    try:
        func = _hash_factories[hash_alg.algorithm_id]
    except KeyError as ex:
        raise NotImplementedError(f'Hash {hash_alg.algorithm_id} not supported') from ex

    return func(hash_alg.parameters)


@dataclass(eq=False)
class CryptographyHash(hashes.HashFunction):
    def __post_init__(self) -> None:
        try:
            self._h = cr_hashes.Hash(create_hash(self.algorithm), backend=backend)
        except (ValueError, UnsupportedAlgorithm) as ex:
            raise NotImplementedError(str(ex)) from ex

    def _finalize(self) -> bytes:
        return self._h.finalize()

    def update(self, data: bytes) -> CryptographyHash:
        self._h.update(data)
        return self

    def copy(self) -> CryptographyHash:
        new = CryptographyHash(self.algorithm)
        new._h = self._h.copy()
        return new


def blake2b(data: bytes, length: int) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return CryptographyHash.hash(hashes.blake2b(length), data)


def blake2s(data: bytes, length: int) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return CryptographyHash.hash(hashes.blake2s(length), data)


def md5(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return CryptographyHash.hash(hashes.md5(), data)


def sha1(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return CryptographyHash.hash(hashes.sha1(), data)


def sha2_224(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return CryptographyHash.hash(hashes.sha2_224(), data)


def sha2_256(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return CryptographyHash.hash(hashes.sha2_256(), data)


def sha2_384(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return CryptographyHash.hash(hashes.sha2_384(), data)


def sha2_512(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return CryptographyHash.hash(hashes.sha2_512(), data)
