from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, ByteString, Optional, Sequence, Union

from ..hashes import HashAlgorithm, MessageDigest, sha2_256
from ..padding import pss
from .key import AsymmetricAlgorithm, PrivateKey, PublicKey, Signature, SignatureMetadata


class RsaScheme(Enum):
    PKCS1v1_5 = auto()
    PKCS1v1_5_RAW = auto()
    PSS = auto()
    RAW = auto()


@dataclass
class Mgf1Parameters:
    hash_alg: Optional[HashAlgorithm] = None


MgfParameters = Union[Mgf1Parameters, Any]


class MgfAlgorithmId(Enum):
    # https://tools.ietf.org/html/rfc8017#appendix-B.2.1
    MGF1 = auto()

    # Other algorithms defined by backends
    OTHER = auto()


@dataclass
class MgfAlgorithm:
    algorithm_id: MgfAlgorithmId
    parameters: Optional[MgfParameters] = None


PSS_SALT_LEN_MAX = -1
PSS_SALT_LEN_HASH = -2


@dataclass(frozen=True)
class PssOptions:
    # Hash algorithm to use for hashing the message and the salted hash.
    hash_alg: Optional[HashAlgorithm] = None

    # Mask Generation Function to use
    mgf_alg: Optional[MgfAlgorithm] = None

    # Length of the salt
    salt_length: Optional[int] = None

    # Value of the salt, or None to use a random salt.
    salt: Optional[bytes] = None

    # Value of trailer field. Usually only BC is supported.
    trailer_field: bytes = b'\xbc'

    def __post_init__(self) -> None:
        if self.salt_length is not None and self.salt is not None and self.salt_length != len(self.salt):
            raise ValueError('salt_length != len(salt)')


def i2osp(x: int, x_len: int) -> bytes:
    """
    Integer to OctetString Primitive:
    https://tools.ietf.org/html/rfc8017#section-4.1
    """

    return int(x).to_bytes(x_len, 'big')


def os2ip(x: ByteString) -> int:
    """
    OctetString to Integer Primitive:
    https://tools.ietf.org/html/rfc8017#section-4.2
    """
    return int.from_bytes(x, 'big')


class RsaPublicKey(PublicKey):
    algorithm = AsymmetricAlgorithm.RSA

    @classmethod
    @abstractmethod
    def from_key(cls, key: PublicKey) -> RsaPublicKey:
        """
        Create a backend key instance from another key.
        """

    @property
    @abstractmethod
    def public_exponent(self) -> int:
        """
        Public RSA exponent (e).
        """

    @property
    @abstractmethod
    def modulus(self) -> int:
        """
        RSA modulus (n).
        """

    @property
    def modlen(self) -> int:
        """
        Length of the modulus in octets.
        This is also the length of signatures.
        """
        return (self.modulus.bit_length() + 7) // 8

    # def encrypt(self, message: bytes) -> bytes:
    #     # XXX Add v15 and OAEP methods; use OAEP if available.
    #     pass


class RsaPrivateKey(PrivateKey):
    algorithm = AsymmetricAlgorithm.RSA

    default_scheme: RsaScheme = RsaScheme.PSS
    default_hash_algorithm: HashAlgorithm = sha2_256()
    default_pss_options: Optional[PssOptions] = None

    @classmethod
    @abstractmethod
    def from_key(cls, key: PrivateKey) -> RsaPrivateKey:
        """
        Create a backend key instance from another key.
        """

    @property
    @abstractmethod
    def public(self) -> RsaPublicKey:
        """
        Get an object that only holds the public portions of the key.
        """

    @property
    def sig_meta(self) -> RsaSignatureMetadata:
        """
        Get default options for signing with sign()
        """
        if self.default_scheme == RsaScheme.PKCS1v1_5:
            return RsaV15Metadata(AsymmetricAlgorithm.RSA, RsaScheme.PKCS1v1_5, self.default_hash_algorithm)
        elif self.default_scheme == RsaScheme.PSS:
            return pss.parse_pss_options(self.public, self.default_hash_algorithm, self.default_pss_options)
        else:
            raise Exception(f'Unsupported scheme: {self.default_scheme}')

    @property
    @abstractmethod
    def private_exponent(self) -> int:
        """
        Private RSA exponent (d).
        """

    @property
    @abstractmethod
    def primes(self) -> Sequence[int]:
        """
        Primes, at least two. XXX q before p?
        """

    # exponents, d % (p - 1) for each prime p
    # coefficients

    @abstractmethod
    async def sign_int(self, msg: int, meta: Optional[RsaSignatureMetadata] = None) -> RsaSignature:
        """
        RSA Signature Primitive version 1, with int input

        https://tools.ietf.org/html/rfc8017#section-5.2.1
        """

    @abstractmethod
    async def sign_bytes(self, msg: bytes, meta: Optional[RsaSignatureMetadata] = None) -> RsaSignature:
        """
        RSA Signature Primitive version 1, with bytes input

        https://tools.ietf.org/html/rfc8017#section-5.2.1
        """

    @abstractmethod
    async def sign_v15_raw(self, msg: bytes, meta: Optional[RsaSignatureMetadata] = None) -> RsaSignature:
        """
        RSA Signature with PKCS#1 v1.5 padding, with Raw or DigestInfo input.

        https://tools.ietf.org/html/rfc8017#section-8.2.1
        https://tools.ietf.org/html/rfc8017#section-9.2
        """

    @abstractmethod
    async def sign_v15_digest(self, dgst: MessageDigest) -> RsaSignature:
        """
        RSA Signature with PKCS#1 v1.5 padding, with prehashed message input.

        https://tools.ietf.org/html/rfc8017#section-8.2.1
        https://tools.ietf.org/html/rfc8017#section-9.2
        """

    @abstractmethod
    async def sign_v15(self, msg: bytes, hash_alg: Optional[HashAlgorithm] = None) -> RsaSignature:
        """
        RSA Signature with PKCS#1 v1.5 padding, with full message input.

        https://tools.ietf.org/html/rfc8017#section-8.2.1
        https://tools.ietf.org/html/rfc8017#section-9.2
        """

    @abstractmethod
    async def sign_pss_digest(self, dgst: MessageDigest, options: Optional[PssOptions] = None) -> RsaSignature:
        """
        RSA Signature with PSS padding, with prehashed message input.

        https://tools.ietf.org/html/rfc8017#section-8.1.1
        https://tools.ietf.org/html/rfc8017#section-9.1.1
        """

    @abstractmethod
    async def sign_pss(self, msg: bytes, options: Optional[PssOptions] = None) -> RsaSignature:
        """
        RSA Signature with PSS padding, with full message input.

        https://tools.ietf.org/html/rfc8017#section-8.1.1
        https://tools.ietf.org/html/rfc8017#section-9.1.1
        """

    @abstractmethod
    async def sign_digest(self, digest: MessageDigest) -> RsaSignature:
        """
        Sign a message that was already hashed.
        """

    @abstractmethod
    async def sign(self, msg: bytes) -> RsaSignature:
        """
        Sign a message.
        """


@dataclass(frozen=True)
class RsaSignatureMetadata(SignatureMetadata):
    """
    Meta data for RSA signatures. Extended by scheme specific sub classes.
    """
    scheme: RsaScheme


@dataclass(frozen=True)
class RsaV15Metadata(RsaSignatureMetadata):
    hash_alg: HashAlgorithm


@dataclass(frozen=True)
class MgfMetadata:
    """
    Meta data for MGF. Extended by mgf specific sub classes.
    """
    algorithm_id: MgfAlgorithmId


@dataclass(frozen=True)
class Mgf1Metadata(MgfMetadata):
    """
    Meta data for MGF1.
    """
    hash_alg: HashAlgorithm


@dataclass(frozen=True)
class OtherMgfMetadata(MgfMetadata):
    """
    Meta data for other custom algorithms.
    """
    params: Any


@dataclass(frozen=True)
class RsaPssMetadata(RsaSignatureMetadata):
    hash_alg: HashAlgorithm
    mgf_alg: MgfMetadata
    salt_length: int
    trailer_field: bytes


@dataclass
class RsaSignature(Signature):
    key: RsaPublicKey = field(repr=False)
    meta: RsaSignatureMetadata
    int_value: int
    bytes_value: bytes

    def __init__(self, key: RsaPublicKey, meta: RsaSignatureMetadata, int_value: Optional[int] = None,
                 bytes_value: Optional[ByteString] = None) -> None:
        self.key = key
        self.meta = meta

        if bytes_value is not None:
            if int_value is not None:
                raise TypeError('Need bytes_value xor int_value')
            self.bytes_value = bytes(bytes_value)
            self.int_value = os2ip(bytes_value)

            # Some implementations might strip or add leading zeros.
            if len(bytes_value) != self.key.modlen:
                self.bytes_value = i2osp(self.int_value, self.key.modlen)
        elif int_value is None:
            raise TypeError('Need bytes_value xor int_value')
        elif int_value < 0:
            raise ValueError('Signature is negative')
        else:
            self.int_value = int_value
            self.bytes_value = i2osp(int_value, self.key.modlen)

        if self.int_value >= self.key.modulus:
            raise ValueError('Signature is not smaller than modulus')
