from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, ByteString, Optional, Sequence, Union, cast

from ..hashes import HashAlgorithm, MessageDigest, sha2_256
from .key import AsymmetricAlgorithm, PrivateKey, PublicKey, Signature, SignatureMetadata


class RsaScheme(Enum):
    PKCS1v1_5 = auto()
    PKCS1v1_5_RAW = auto()
    PSS = auto()
    RAW = auto()


@dataclass(frozen=True)
class Mgf1Parameters:
    hash_alg: Optional[HashAlgorithm] = None


MgfParameters = Union[Mgf1Parameters, Any]


class MgfAlgorithmId(Enum):
    # https://tools.ietf.org/html/rfc8017#appendix-B.2.1
    MGF1 = auto()

    # Other algorithms defined by backends
    OTHER = auto()


@dataclass(frozen=True)
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
    trailer_field: bytes = b"\xbc"

    def __post_init__(self) -> None:
        if self.salt_length is not None and self.salt is not None and self.salt_length != len(self.salt):
            raise ValueError("salt_length != len(salt)")


def i2osp(x: int, x_len: int) -> bytes:
    """
    Integer to OctetString Primitive:
    https://tools.ietf.org/html/rfc8017#section-4.1
    """

    return int(x).to_bytes(x_len, "big")


def os2ip(x: ByteString) -> int:
    """
    OctetString to Integer Primitive:
    https://tools.ietf.org/html/rfc8017#section-4.2
    """
    return int.from_bytes(x, "big")


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

    @property
    def mod_bits(self) -> int:
        """
        Length of the modulus in bits.
        """
        return self.modulus.bit_length()

    # def encrypt(self, message: bytes) -> bytes:
    #     # XXX Add v15 and OAEP methods; use OAEP if available.
    #     pass


class RsaPrivateKey(PrivateKey):
    algorithm = AsymmetricAlgorithm.RSA

    default_scheme: RsaScheme = RsaScheme.PSS
    default_hash_algorithm: HashAlgorithm = sha2_256()
    default_pss_options: Optional[PssOptions] = None

    @classmethod
    def from_key(cls, key: PrivateKey) -> RsaPrivateKey:
        """
        Create a backend key instance from another key.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def public(self) -> RsaPublicKey:
        """
        Get an object that only holds the public portions of the key.
        """

    @property
    def sig_meta(self) -> RsaSignatureMetadata:
        # XXX add setters for default_* and have them set this property?
        """
        Get default options for signing with sign()
        """
        if self.default_scheme == RsaScheme.PKCS1v1_5:
            return RsaV15Metadata(AsymmetricAlgorithm.RSA, RsaScheme.PKCS1v1_5, self.default_hash_algorithm)
        elif self.default_scheme == RsaScheme.PSS:
            return parse_pss_options(self.public, self.default_hash_algorithm, self.default_pss_options)
        else:
            raise Exception(f"Unsupported scheme: {self.default_scheme}")

    @property
    def private_exponent(self) -> int:
        """
        Private RSA exponent (d).
        """
        raise NotImplementedError

    @property
    def primes(self) -> Sequence[int]:
        """
        Primes, at least two. XXX q before p?
        """
        raise NotImplementedError

    # exponents, d % (p - 1) for each prime p
    # coefficients

    async def sign_int(self, msg: int, meta: Optional[RsaSignatureMetadata] = None) -> RsaSignature:
        """
        RSA Signature Primitive version 1, with int input

        https://tools.ietf.org/html/rfc8017#section-5.2.1
        """
        raise NotImplementedError

    async def sign_bytes(self, msg: bytes, meta: Optional[RsaSignatureMetadata] = None) -> RsaSignature:
        """
        RSA Signature Primitive version 1, with bytes input

        https://tools.ietf.org/html/rfc8017#section-5.2.1
        """
        raise NotImplementedError

    async def sign_v15_raw(self, msg: bytes, meta: Optional[RsaSignatureMetadata] = None) -> RsaSignature:
        """
        RSA Signature with PKCS#1 v1.5 padding, with Raw or DigestInfo input.

        https://tools.ietf.org/html/rfc8017#section-8.2.1
        https://tools.ietf.org/html/rfc8017#section-9.2
        """
        raise NotImplementedError

    async def sign_v15_digest(self, dgst: MessageDigest) -> RsaSignature:
        """
        RSA Signature with PKCS#1 v1.5 padding, with prehashed message input.

        https://tools.ietf.org/html/rfc8017#section-8.2.1
        https://tools.ietf.org/html/rfc8017#section-9.2
        """
        raise NotImplementedError

    async def sign_v15(self, msg: bytes, hash_alg: Optional[HashAlgorithm] = None) -> RsaSignature:
        """
        RSA Signature with PKCS#1 v1.5 padding, with full message input.

        https://tools.ietf.org/html/rfc8017#section-8.2.1
        https://tools.ietf.org/html/rfc8017#section-9.2
        """
        raise NotImplementedError

    async def sign_pss_digest(self, dgst: MessageDigest, options: Optional[PssOptions] = None) -> RsaSignature:
        """
        RSA Signature with PSS padding, with prehashed message input.

        https://tools.ietf.org/html/rfc8017#section-8.1.1
        https://tools.ietf.org/html/rfc8017#section-9.1.1
        """
        raise NotImplementedError

    async def sign_pss(self, msg: bytes, options: Optional[PssOptions] = None) -> RsaSignature:
        """
        RSA Signature with PSS padding, with full message input.

        https://tools.ietf.org/html/rfc8017#section-8.1.1
        https://tools.ietf.org/html/rfc8017#section-9.1.1
        """
        raise NotImplementedError

    async def sign_digest(self, digest: MessageDigest) -> RsaSignature:
        """
        Sign a message that was already hashed.
        """
        raise NotImplementedError

    async def sign(self, msg: bytes) -> RsaSignature:
        """
        Sign a message.
        """
        raise NotImplementedError


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


@dataclass(frozen=True)
class RsaSignature(Signature):
    key: RsaPublicKey = field(repr=False)
    meta: RsaSignatureMetadata
    int_value: int
    bytes_value: bytes

    @classmethod
    def from_int(cls, key: RsaPublicKey, meta: RsaSignatureMetadata, value: int) -> RsaSignature:
        if value < 0:
            raise ValueError("Signature is negative")
        return cls(key, meta, value, i2osp(value, key.modlen))

    @classmethod
    def from_bytes(cls, key: RsaPublicKey, meta: RsaSignatureMetadata, value: ByteString) -> RsaSignature:
        int_value = os2ip(value)
        # Some implementations might strip or add leading zeros.
        if len(value) != key.modlen:
            value = i2osp(int_value, key.modlen)
        else:
            value = bytes(value)
        return cls(key, meta, int_value, value)

    def __post_init__(self) -> None:
        if self.int_value >= self.key.modulus:
            raise ValueError("Signature is not smaller than modulus")


def parse_pss_options(
    pub: RsaPublicKey,
    default_hash_alg: HashAlgorithm,
    options: Optional[PssOptions] = None,
    dgst_hash_alg: Optional[HashAlgorithm] = None,
) -> RsaPssMetadata:
    """"""

    opt = options or PssOptions()

    if dgst_hash_alg and opt.hash_alg and dgst_hash_alg != opt.hash_alg:
        raise TypeError("conflicting hash algorithms")
    hash_alg = dgst_hash_alg or opt.hash_alg or default_hash_alg

    opt_mgf = opt.mgf_alg or MgfAlgorithm(MgfAlgorithmId.MGF1)

    mgf_alg: MgfMetadata  # mypy doesn't see that below Mgf1Metadata and OtherMgfMetadata have same parent type.

    if opt_mgf.algorithm_id == MgfAlgorithmId.MGF1:
        mgf_params = cast(Mgf1Parameters, opt_mgf.parameters) if opt_mgf.parameters else Mgf1Parameters()
        mgf_alg = Mgf1Metadata(MgfAlgorithmId.MGF1, mgf_params.hash_alg or hash_alg)
    elif opt_mgf.algorithm_id == MgfAlgorithmId.OTHER:
        mgf_alg = OtherMgfMetadata(MgfAlgorithmId.OTHER, opt_mgf.parameters)
    else:
        raise NotImplementedError(f"MGF algorithm {opt_mgf.algorithm_id} not implemented")

    salt_length = calculate_pss_salt_len(pub.modulus.bit_length(), opt, hash_alg.size)

    return RsaPssMetadata(
        algorithm=AsymmetricAlgorithm.RSA,
        scheme=RsaScheme.PSS,
        hash_alg=hash_alg,
        mgf_alg=mgf_alg,
        salt_length=salt_length,
        trailer_field=opt.trailer_field,
    )


def calculate_pss_salt_len(mod_bits: int, opt: PssOptions, dgst_len: int) -> int:
    """
    Calculate and validate the length of the salt.

    Args:
        mod_bits: length of the modulus in bits
        opt: Pss Options; may contain None values
        dgst_len: length of digest in bytes

    Returns:
        Salt length in bytes
    """

    # 8.1.1/1) One less modulus size to ensure that the encoded message is always smaller than the modulus.
    em_bits = mod_bits - 1

    if dgst_len < 0:
        raise ValueError("dgst_len cannot be negative")

    if em_bits < 0:
        raise ValueError("em_bits cannot be negative")

    # 9.1.1/Output)
    em_len = (em_bits + 7) // 8

    # Usually 1 (for b'\xbc')
    trailer_len = len(opt.trailer_field)

    # 9.1.1/3) specifies the upper bound of salt_len. Rationale:
    #
    # 9.1.1/8) db_len = ps_len + 1 + salt_len
    # 9.1.1/10) mask_len = db_len
    # 9.1.1/12) em_len = mask_len + dgst_len + trailer_len
    # => salt_len = em_len - 1 - dgst_len - trailer_len - ps_len
    # 9.1.1/7) allows ps_len = 0.
    # => max_salt_len = em_len - 1 - dgst_len - trailer_len
    max_salt_len = em_len - 1 - dgst_len - trailer_len

    if max_salt_len < 0:
        raise ValueError("Maximum salt length cannot be negative")

    if opt.salt_length is None:
        salt_len = max_salt_len if opt.salt is None else len(opt.salt)
    elif opt.salt_length == PSS_SALT_LEN_MAX:
        salt_len = max_salt_len
    elif opt.salt_length == PSS_SALT_LEN_HASH:
        # Try to use digest len (9.1/4), but if it's bigger than max_salt_len, use that.
        salt_len = min(dgst_len, max_salt_len)
    else:
        if opt.salt_length < 0:
            raise ValueError("salt_length cannot be negative")

        salt_len = opt.salt_length

    if salt_len > max_salt_len:
        raise ValueError("Requested salt length too big")

    return salt_len
