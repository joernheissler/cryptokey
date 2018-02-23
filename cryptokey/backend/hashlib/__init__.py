from __future__ import annotations

import hashlib
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, cast

from ... import hashes
from ...hashes import HashAlgorithmId


class _HashlibHash(metaclass=ABCMeta):
    """
    Class used to help the type annotations
    """

    @abstractmethod
    def update(self, data: bytes) -> None:
        """"""

    @abstractmethod
    def digest(self, length: Optional[int] = None) -> bytes:
        """"""

    @property
    @abstractmethod
    def digest_size(self) -> int:
        """"""

    @abstractmethod
    def copy(self) -> _HashlibHash:
        """"""


@dataclass(eq=False)
class HashlibHash(hashes.HashFunction):
    def __post_init__(self) -> None:
        self._hash = self._create_hash()

    def update(self, data: bytes) -> HashlibHash:
        self._hash.update(data)
        return self

    def _finalize(self) -> bytes:
        f = _algos[self.algorithm.algorithm_id][2]
        params: Tuple[Any, ...]
        if f is None:
            params = ()
        elif isinstance(f, int):
            params = (f,)
        else:
            params = (f(self.algorithm.parameters),)

        return self._hash.digest(*params)

    def _create_hash(self) -> _HashlibHash:
        try:
            name, init, __, __ = _algos[self.algorithm.algorithm_id]
        except KeyError:
            raise NotImplementedError

        init_params = init(self.algorithm.parameters) if init else {}

        try:
            f = getattr(hashlib, name)
        except AttributeError:
            try:
                return cast(_HashlibHash, hashlib.new(name, **init_params))
            except ValueError:
                raise NotImplementedError
        else:
            return cast(_HashlibHash, f(**init_params))

    def copy(self) -> HashlibHash:
        new = HashlibHash(self.algorithm)
        new._hash = self._hash.copy()
        return new


def _blake2_len(params: hashes.HashParameters) -> Dict[str, int]:
    return {'digest_size': cast(hashes.Blake2Params, params).length}


def _shake_len(params: hashes.HashParameters) -> int:
    return cast(hashes.ShakeLenParams, params).length


_algos = {
    HashAlgorithmId.BLAKE2B: ('blake2b', _blake2_len, None, None),
    HashAlgorithmId.BLAKE2S: ('blake2s', _blake2_len, None, None),

    HashAlgorithmId.MD5: ('md5', None, None, None),
    HashAlgorithmId.RIPEMD_160: ('ripemd160', None, None, None),
    HashAlgorithmId.SHA1: ('sha1', None, None, None),
    HashAlgorithmId.SHA2_224: ('sha224', None, None, None),
    HashAlgorithmId.SHA2_256: ('sha256', None, None, None),
    HashAlgorithmId.SHA2_384: ('sha384', None, None, None),
    HashAlgorithmId.SHA2_512: ('sha512', None, None, None),
    HashAlgorithmId.SHA2_512_224: ('sha512-224', None, None, None),
    HashAlgorithmId.SHA2_512_256: ('sha512-256', None, None, None),

    HashAlgorithmId.SHA3_224: ('sha3_224', None, None, None),
    HashAlgorithmId.SHA3_256: ('sha3_256', None, None, None),
    HashAlgorithmId.SHA3_384: ('sha3_384', None, None, None),
    HashAlgorithmId.SHA3_512: ('sha3_512', None, None, None),

    HashAlgorithmId.SHAKE_128: ('shake_128', None, 16, None),
    HashAlgorithmId.SHAKE_256: ('shake_256', None, 32, None),
    HashAlgorithmId.SHAKE_128_LEN: ('shake_128', None, _shake_len, _shake_len),
    HashAlgorithmId.SHAKE_256_LEN: ('shake_256', None, _shake_len, _shake_len),

    HashAlgorithmId._TEST_DUMMY: ('test_dummy', None, None, None),
}


def blake2b(data: bytes, length: int) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.blake2b(length), data)


def blake2s(data: bytes, length: int) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.blake2s(length), data)


def md5(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.md5(), data)


def ripemd_160(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.ripemd_160(), data)


def sha1(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha1(), data)


def sha2_224(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha2_224(), data)


def sha2_256(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha2_256(), data)


def sha2_384(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha2_384(), data)


def sha2_512(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha2_512(), data)


def sha2_512_224(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha2_512_224(), data)


def sha2_512_256(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha2_512_256(), data)


def sha3_224(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha3_224(), data)


def sha3_256(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha3_256(), data)


def sha3_384(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha3_384(), data)


def sha3_512(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.sha3_512(), data)


def shake_128(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.shake_128(), data)


def shake_128_len(data: bytes, length: int) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.shake_128_len(length), data)


def shake_256(data: bytes) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.shake_256(), data)


def shake_256_len(data: bytes, length: int) -> hashes.MessageDigest:
    """
    Convenience function to hash a message.
    """
    return HashlibHash.hash(hashes.shake_256_len(length), data)
