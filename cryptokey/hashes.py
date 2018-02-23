"""
This module defines algorithms and interfaces for cryptographic hash functions.
"""
from __future__ import annotations

from abc import ABCMeta, abstractmethod
from dataclasses import InitVar, dataclass, field
from enum import Enum
from typing import Callable, Mapping, Optional, Tuple, Type, Union, cast

from .oid import OID, ObjectIdentifier

# https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash
OID_NIST_HASHES = OID-2-16-840-1-101-3-4-2

# https://tools.ietf.org/html/rfc7693.html
OID_KUDELSKI_HASH = OID-1-3-6-1-4-1-1722-12-2
OID_BLAKE2B = OID_KUDELSKI_HASH-1
OID_BLAKE2S = OID_KUDELSKI_HASH-2


@dataclass
class Blake2Params:
    """
    Parameters for blake2 algorithm.
    """
    length: int


def blake2b_oid(alg: HashAlgorithm) -> ObjectIdentifier:
    """
    Determine OID from algorithm.
    """
    length = cast(Blake2Params, alg.parameters).length
    if length % 4:
        raise ValueError('Blake2 only has OIDs for multiples of 32 bit')
    return OID_BLAKE2B-(length // 4)


def blake2s_oid(alg: HashAlgorithm) -> ObjectIdentifier:
    """
    Determine OID from algorithm.
    """
    length = cast(Blake2Params, alg.parameters).length
    if length % 4:
        raise ValueError('Blake2 only has OIDs for multiples of 32 bit')
    return OID_BLAKE2S-(length // 4)


def blake2_size(alg: HashAlgorithm) -> int:
    """
    Determine size of digest from algorithm.
    """
    return cast(Blake2Params, alg.parameters).length


@dataclass
class ShakeLenParams:
    """
    Parameters for shake algorithm.
    """
    length: int


def shake_len_size(alg: HashAlgorithm) -> int:
    """
    Determine size of digest from algorithm.
    """
    return cast(ShakeLenParams, alg.parameters).length


HashParameters = Union[None, Blake2Params, ShakeLenParams]


@dataclass(frozen=True)
class HashAlgorithm:
    """
    Hash Algorithm.
    algorithm_id specifies which algorithm to use,
    parameters specifies any algorithm specific parameters, e.g. digest size.
    """
    algorithm_id: HashAlgorithmId
    parameters: Optional[HashParameters] = None


_algos: Mapping[
    str,
    Tuple[
        Union[
            None,
            ObjectIdentifier,
            Callable[[HashAlgorithm], ObjectIdentifier],
        ],
        Union[
            int,
            Callable[[HashAlgorithm], int],
        ],
        Optional[Type[HashParameters]],
    ]
] = {
    'BLAKE2B': (blake2b_oid, blake2_size, Blake2Params),
    'BLAKE2S': (blake2s_oid, blake2_size, Blake2Params),
    'MD5': (OID-1-2-840-113549-2-5, 16, None),
    'RIPEMD_160': (OID-1-3-36-3-2-1, 20, None),
    'SHA1': (OID-1-3-14-3-2-26, 20, None),
    'SHA2_224': (OID_NIST_HASHES-4, 28, None),
    'SHA2_256': (OID_NIST_HASHES-1, 32, None),
    'SHA2_384': (OID_NIST_HASHES-2, 48, None),
    'SHA2_512': (OID_NIST_HASHES-3, 64, None),
    'SHA2_512_224': (OID_NIST_HASHES-5, 28, None),
    'SHA2_512_256': (OID_NIST_HASHES-6, 32, None),
    'SHA3_224': (OID_NIST_HASHES-7, 28, None),
    'SHA3_256': (OID_NIST_HASHES-8, 32, None),
    'SHA3_384': (OID_NIST_HASHES-9, 48, None),
    'SHA3_512': (OID_NIST_HASHES-10, 64, None),
    'SHAKE_128': (OID_NIST_HASHES-11, 16, None),
    'SHAKE_128_LEN': (OID_NIST_HASHES-17, shake_len_size, ShakeLenParams),
    'SHAKE_256': (OID_NIST_HASHES-12, 32, None),
    'SHAKE_256_LEN': (OID_NIST_HASHES-18, shake_len_size, ShakeLenParams),
    '_TEST_DUMMY': (None, 3, None),
}

# MyPy doesn't work with list(_algos.keys())
HashAlgorithmId = Enum('HashAlgorithmId', [
    'BLAKE2B',
    'BLAKE2S',
    'MD5',
    'RIPEMD_160',
    'SHA1',
    'SHA2_224',
    'SHA2_256',
    'SHA2_384',
    'SHA2_512',
    'SHA2_512_224',
    'SHA2_512_256',
    'SHA3_224',
    'SHA3_256',
    'SHA3_384',
    'SHA3_512',
    'SHAKE_128',
    'SHAKE_128_LEN',
    'SHAKE_256',
    'SHAKE_256_LEN',
    '_TEST_DUMMY',
])

_hash_oids = {getattr(HashAlgorithmId, k): algo[0] for k, algo in _algos.items()}
_hash_sizes = {getattr(HashAlgorithmId, k): algo[1] for k, algo in _algos.items()}
for k, algo in _algos.items():
    pass


def get_algo_oid(alg: HashAlgorithm) -> ObjectIdentifier:
    """
    Object identifier for this hash function.
    It might vary with different parameters.
    """
    oid = _hash_oids[alg.algorithm_id]
    if oid is None:
        raise ValueError('No OID defined')

    if isinstance(oid, ObjectIdentifier):
        return oid

    return oid(alg)


def get_algo_size(alg: HashAlgorithm) -> int:
    """
    Get digest size by algorithm.
    """
    size = _hash_sizes[alg.algorithm_id]
    if isinstance(size, int):
        return size

    return size(alg)


@dataclass
class MessageDigest:
    """
    Result from a hash function.
    `value` is the message digest.
    `hashobj` is the hash function instance that created this digest.
    `algorithm` is the hash algorithm + parameters used to create this digest.
    `hashfunc` is a class which can be instantiated to create more digests with the same set of parameters.
    """
    value: bytes
    hashobj: InitVar[HashFunction]
    algorithm: HashAlgorithm = field(init=False)
    hashfunc: Type[HashFunction] = field(init=False, compare=False, repr=False)

    def __post_init__(self, hashobj: HashFunction) -> None:
        self.algorithm = hashobj.algorithm
        self.hashfunc = type(hashobj)

    def new(self) -> HashFunction:
        """
        Create a new instance of the hash function which generated this Digest.
        """
        return self.hashfunc(self.algorithm)

    @property
    def oid(self) -> ObjectIdentifier:
        """
        Object identifier for this hash function.
        It might vary with different parameters.
        """
        return get_algo_oid(self.algorithm)

    @property
    def size(self) -> int:
        """
        Size of the digest in bytes.
        """
        return len(self.value)

    @property
    def hexvalue(self) -> str:
        """
        Digest in lower case hexadecimal representation.
        """
        return self.value.hex()

    def __bytes__(self) -> bytes:
        """
        Byte representation of digest.
        """
        return self.value

    def __len__(self) -> int:
        """
        Size of the digest in bytes.
        """
        return len(self.value)


@dataclass(eq=False)
class HashFunction(metaclass=ABCMeta):
    """
    Represents a hash function like SHA2-256; each instance of this class is used to calculate one
    MessageDigest.
    """

    algorithm: HashAlgorithm
    _digest: Optional[MessageDigest] = field(default=None, init=False)

    @classmethod
    def hash(cls, alg: HashAlgorithm, data: bytes) -> MessageDigest:
        """
        One-shot function to create a digest with a single call.
        Needs to be called on an implementing class.

        Example: digest = cryptokey.hashlib.SHA256.hash(b'Message')
        """
        return cls(alg).update(data).finalize()

    def finalize(self) -> MessageDigest:
        """
        Finalize the digest computation and return the MessageDigest.
        """
        if self._digest is None:
            self._digest = MessageDigest(self._finalize(), self)
        return self._digest

    @abstractmethod
    def _finalize(self) -> bytes:
        """
        Finalize digest and return it.
        This function is called at most once.
        """

    @abstractmethod
    def update(self, data: bytes) -> HashFunction:
        """
        Update state with `data` and return self.
        """

    @property
    def oid(self) -> ObjectIdentifier:
        """
        Object identifier for this hash function.
        It might vary with different parameters.
        """
        return get_algo_oid(self.algorithm)

    @property
    def size(self) -> int:
        """
        Size of the digest in bytes.
        """
        return get_algo_size(self.algorithm)

    @abstractmethod
    def copy(self) -> HashFunction:
        """
        Create a copy of this hash function. Both instances can the be updated individually.
        """


def blake2b(length: int) -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    `length` is the digest size.
    """
    return HashAlgorithm(HashAlgorithmId.BLAKE2B, Blake2Params(length))


def blake2s(length: int) -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    `length` is the digest size.
    """
    return HashAlgorithm(HashAlgorithmId.BLAKE2S, Blake2Params(length))


def md5() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.MD5)


def ripemd_160() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.RIPEMD_160)


def sha1() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA1)


def sha2_224() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA2_224)


def sha2_256() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA2_256)


def sha2_384() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA2_384)


def sha2_512() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA2_512)


def sha2_512_224() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA2_512_224)


def sha2_512_256() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA2_512_256)


def sha3_224() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA3_224)


def sha3_256() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA3_256)


def sha3_384() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA3_384)


def sha3_512() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHA3_512)


def shake_128() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHAKE_128)


def shake_128_len(length: int) -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    `length` is the digest size.
    """
    return HashAlgorithm(HashAlgorithmId.SHAKE_128_LEN, ShakeLenParams(length))


def shake_256() -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    """
    return HashAlgorithm(HashAlgorithmId.SHAKE_256)


def shake_256_len(length: int) -> HashAlgorithm:
    """
    Convenience function to create hash algorithm object.
    `length` is the digest size.
    """
    return HashAlgorithm(HashAlgorithmId.SHAKE_256_LEN, ShakeLenParams(length))
