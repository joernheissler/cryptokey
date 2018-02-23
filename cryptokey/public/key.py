from __future__ import annotations

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto

from ..hashes import MessageDigest


class AsymmetricAlgorithm(Enum):
    DSA = auto()
    ECDSA = auto()
    ELGAMAL = auto()
    RSA = auto()


class PublicKey(metaclass=ABCMeta):
    # @property
    # @abstractmethod
    # def encrypt_options(self) -> Any:
    #     """
    #     Get default options for encrypting with encrypt()
    #     """
    #     # XXX More specific than Any?

    @classmethod
    @abstractmethod
    def from_key(cls, key: PublicKey) -> PublicKey:
        """
        Create a backend key instance from another key.
        """

    @property
    @abstractmethod
    def algorithm(self) -> AsymmetricAlgorithm:
        """
        Algorithm
        """

    @abstractmethod
    def export_public_der(self) -> bytes:
        """
        """

    @abstractmethod
    def export_public_pem(self) -> str:
        """
        """

    @abstractmethod
    def export_public_openssh(self) -> str:
        """
        """

    # @abstractmethod
    # def validate(self) -> None:
    #     """
    #     Run some checks on the key to determine if it's valid. E.g. for an RSA private
    #     key this could mean that the modulus is the product of the primes. An EC public
    #     key could check if its point is on the curve.
    #     """

    #  @abstractmethod
    #  def verify(self, signature: Signature, message: bytes) -> None:
    #      """
    #      Validate if a signature is valid for a message.
    #      """

    #  @abstractmethod
    #  def verify_digest(self, signature: Signature, digest: MessageDigest) -> None:
    #      """
    #      Validate if a signature is valid for a message.
    #      """

    #  @abstractmethod
    #  def encrypt(self, message: bytes) -> bytes:
    #      """
    #      Encrypt a message to a ciphertext.
    #      """
    #      # XXX should there be a class for the return value? See what e.g. CMS needs.


class PrivateKey(metaclass=ABCMeta):
    @property
    @abstractmethod
    def sig_meta(self) -> SignatureMetadata:
        """
        Get default options for signing with sign()
        """

    @classmethod
    @abstractmethod
    def from_key(cls, key: PrivateKey) -> PrivateKey:
        """
        Create a backend key instance from another key.
        """

    @property
    @abstractmethod
    def algorithm(self) -> AsymmetricAlgorithm:
        """
        Algorithm
        """

    @property
    @abstractmethod
    def public(self) -> PublicKey:
        """
        Get an object that only holds the public portions of the key.
        """

    @abstractmethod
    def export_private_der(self) -> bytes:
        """
        """

    @abstractmethod
    def export_private_pem(self) -> str:
        """
        """

    @abstractmethod
    def export_private_openssh(self) -> str:
        """
        """

    @abstractmethod
    async def sign_digest(self, digest: MessageDigest) -> Signature:
        """
        Sign a message that was already hashed.
        """

    @abstractmethod
    async def sign(self, msg: bytes) -> Signature:
        """
        Sign a message.
        """

    # @abstractmethod
    # async def decrypt(self, ciphertext: bytes) -> bytes:
    #     """
    #     Decrypt a ciphertext to a message.
    #     """


@dataclass(frozen=True)
class SignatureMetadata:
    """
    Meta data for signatures. Extended by algorithm specific sub classes.
    """
    algorithm: AsymmetricAlgorithm


@dataclass
class Signature:
    """
    Result of a sign operation.
    """
    key: PublicKey = field(repr=False)
    meta: SignatureMetadata

    @property
    def algorithm(self) -> AsymmetricAlgorithm:
        """
        Algorithm
        """
        return self.meta.algorithm

    # def verify(self, message: bytes) -> None:
    #     self.key.verify(self, message)

    # def verify_digest(self, digest: MessageDigest) -> None:
    #     self.key.verify_digest(self, digest)
