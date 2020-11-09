from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import ByteString, Optional, Union

from asn1crypto.algos import DSASignature

from ..hashes import HashAlgorithm, MessageDigest, sha2_256
from .ecc import CurveId, CurvePoint
from .key import AsymmetricAlgorithm, PrivateKey, PublicKey, Signature, SignatureMetadata


class UniqueKey(Enum):
    # use library default
    DEFAULT = auto()

    # generate random k
    RANDOM = auto()

    # generate k in accordance with rfc6979
    RFC6979 = auto()


UniqueKeyParam = Union[UniqueKey, int]


@dataclass(frozen=True)
class EcdsaSignatureMetadata(SignatureMetadata):
    """
    Meta data for ECDSA signatures.
    """

    hash_alg: HashAlgorithm


@dataclass(frozen=True)
class EcdsaSignature(Signature):
    key: EccPublicKey = field(repr=False)
    meta: EcdsaSignatureMetadata
    r: int
    s: int
    der: bytes

    @classmethod
    def create(
        cls,
        key: EccPublicKey,
        meta: EcdsaSignatureMetadata,
        r: Optional[int] = None,
        s: Optional[int] = None,
        der: Optional[ByteString] = None,
    ) -> None:
        """"""

        if not r and not s and der:
            val = DSASignature.load(der)
            return cls(key, meta, val["r"].native, val["s"].native, bytes(der))

        if r and s and not der:
            return cls(key, meta, r, s, DSASignature({"r": r, "s": s}).dump())

        raise ValueError("Bad parameters")


class EccPublicKey(PublicKey):
    algorithm = AsymmetricAlgorithm.ECDSA

    @classmethod
    @abstractmethod
    def from_key(cls, key: PublicKey) -> EccPublicKey:
        """
        Create a backend key instance from another key.
        """

    @property
    @abstractmethod
    def point(self) -> CurvePoint:
        """
        Public key's point
        """

    @property
    def curve_id(self) -> CurveId:
        return self.point.curve_id


class EccPrivateKey(PrivateKey):
    algorithm = AsymmetricAlgorithm.ECDSA

    default_hash_algorithm: HashAlgorithm = sha2_256()

    @classmethod
    def from_key(cls, key: PrivateKey) -> EccPrivateKey:
        """
        Create a backend key instance from another key.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def public(self) -> EccPublicKey:
        """
        Get an object that only holds the public portions of the key.
        """

    @property
    def sig_meta(self) -> EcdsaSignatureMetadata:
        """
        Get default options for signing with sign()
        """
        return EcdsaSignatureMetadata(AsymmetricAlgorithm.ECDSA, self.default_hash_algorithm)

    @property
    @abstractmethod
    def curve_id(self) -> CurveId:
        """
        Curve
        """

    @property
    def private_exponent(self) -> int:
        """
        Private ECC exponent (d).
        """
        raise NotImplementedError

    async def sign_digest_dsa(
        self, digest: MessageDigest, k: UniqueKeyParam = UniqueKey.DEFAULT
    ) -> EcdsaSignature:
        """"""
        raise NotImplementedError

    async def sign_dsa(
        self, msg: bytes, hash_alg: Optional[HashAlgorithm] = None, k: UniqueKeyParam = UniqueKey.DEFAULT
    ) -> EcdsaSignature:
        """"""
        raise NotImplementedError

    async def sign_digest(self, digest: MessageDigest) -> EcdsaSignature:
        return await self.sign_digest_dsa(digest)

    async def sign(self, msg: bytes) -> EcdsaSignature:
        return await self.sign_dsa(msg)
