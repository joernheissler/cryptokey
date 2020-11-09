from __future__ import annotations

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Mapping, Optional

from asn1crypto.keys import PublicKeyInfo

from ..hashes import MessageDigest


class AsymmetricAlgorithm(Enum):
    DSA = auto()  # XXX Not an actual key algorithm
    ECDSA = auto()  # XXX Not an actual key algorithm
    ELGAMAL = auto()  # XXX Not an actual key algorithm
    RSA = auto()
    ED25519 = auto()
    X25519 = auto()


class PublicKey(metaclass=ABCMeta):
    """
    Abstract base class for public keys.
    """

    @classmethod
    @abstractmethod
    def from_key(cls, key: PublicKey) -> PublicKey:
        """
        Create a public key instance from another public key (e.g. from other backend)
        with the same algorithm.

        Args:
            key: Another public key

        Returns:
            Newly created public key
        """

    @property
    @abstractmethod
    def algorithm(self) -> AsymmetricAlgorithm:
        """
        Algorithm of this key. Usually implemented as a class constant.
        """

    def to_keyinfo_der(self) -> bytes:
        """
        Convert public key to SubjectPublicKeyInfo as defined by :rfc:`5280#section-4.1`.

        Same as ``openssl pkey -pubout -outform der``.

        Returns:
            DER encoded SubjectPublicKeyInfo
        """

        raise NotImplementedError

    def to_keyinfo_pem(self) -> str:
        """
        Convert public key to SubjectPublicKeyInfo as defined by :rfc:`5280#section-4.1`, and format output as PEM.
        Output starts with ``-----BEGIN PUBLIC KEY-----``.

        Same as ``openssl pkey -pubout -outform pem``.

        Returns:
            PEM encoded SubjectPublicKeyInfo
        """

        raise NotImplementedError

    def to_keyinfo_asn1crypto(self) -> PublicKeyInfo:
        """
        Convert public key to asn1crypto ``PublicKeyInfo`` object.

        Returns:
            ``PublicKeyInfo`` object.
        """

        raise NotImplementedError

    def to_openssl_der(self) -> bytes:
        """
        Convert public key to legacy/traditional openssl format. The result doesn't include information
        about what type of key was exported. If in doubt, use :py:meth:`to_keyinfo_der`.

        Same as e.g. ``openssl rsa -RSAPublicKey_out -outform der``.

        Returns:
            DER encoded public key in legacy/traditional openssl format. 
        """

        raise NotImplementedError

    def to_openssl_pem(self) -> str:
        """
        Convert public key to legacy/traditional openssl format. The result includes information
        about what type of key was exported only in the PEM header, not in the contents.
        Output starts with ``-----BEGIN RSA PUBLIC KEY-----`` or similar.

        If in doubt, use :py:meth:`to_keyinfo_pem`.

        Same as e.g. ``openssl rsa -RSAPublicKey_out -outform pem``.

        Returns:
            PEM encoded public key in legacy/traditional openssl format. 
        """

        raise NotImplementedError

    def to_openssh_rfc4716(self) -> str:
        """
        Convert public key to modern OpenSSH public key format as defined by :rfc:`4716`.

        Output starts with ``---- BEGIN SSH2 PUBLIC KEY ----``.

        Same as e.g. ``ssh-keygen -e -m rfc4716``.

        Returns:
            RFC4716 encoded public key
        """

        raise NotImplementedError

    def to_openssl_rfc4253(self) -> bytes:
        """
        Convert public key to OpenSSH binary format as defined by :rfc:`rfc4253#section-6.6´.

        Same as the contents of :py:meth:`to_openssh_rfc4716` or :py:meth:`to_openssh_authkey`.

        Returns:
            RFC4253 encoded public key
        """

        raise NotImplementedError

    def to_openssh_authkey(self) -> str:
        """
        Convert public key to OpenSSH authorized_keys format as defined in ``man 8 sshd``.

        Same as e.g. ``ssh-keygen -y``.

        Returns:
            Encoded public key
        """

        raise NotImplementedError

    def to_jwk(self, fields: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        """
        Convert public key to a JSON Web Key as defined by :rfc:`rfc7517#section-4` and :rfc:`rfc7518#section-6`.

        Args:
            fields: Optional JWK fields to copy into the result, e.g. ``kid`` or ``alg``.

        Returns:
            Dictionary with ``kty`` and other members defined by that algorithm plus :py:obj:`fields`. Each call
            to this function returns a new object; it may be modified by the caller, e.g. to add more optional
            fields.
        """

        raise NotImplementedError


    # @abstractmethod
    # def validate(self) -> None:
    #     """
    #     Run some checks on the key to determine if it's valid. E.g. for an RSA private
    #     key this could mean that the modulus is the product of the primes. An EC public
    #     key could check if its point is on the curve.
    #     """

    #  def verify(self, signature: Signature, message: bytes) -> None:
    #      """
    #      Validate if a signature is valid for a message.
    #      """

    #  def verify_digest(self, signature: Signature, digest: MessageDigest) -> None:
    #      """
    #      Validate if a signature is valid for a message.
    #      """

    #  def encrypt(self, message: bytes) -> bytes:
    #      """
    #      Encrypt a message to a ciphertext.
    #      """
    #      # XXX should there be a class for the return value? See what e.g. CMS needs.


class PrivateKey(metaclass=ABCMeta):
    """
    Abstract base class for private keys.
    """

    @classmethod
    def from_key(cls, key: PrivateKey) -> PrivateKey:
        """
        Create a private key instance from another private key (e.g. from other backend)
        with the same algorithm.

        Args:
            key: Another private key

        Returns:
            Newly created private key
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def algorithm(self) -> AsymmetricAlgorithm:
        """
        Algorithm of this key. Usually implemented as a class constant.
        """

    @property
    @abstractmethod
    def public(self) -> PublicKey:
        """
        Get an object that only holds the public portions of the key.

        Returns:
            The public key bound to this private key.
        """

    @property
    def sig_meta(self) -> SignatureMetadata:
        """
        Get default options for signing with sign()
        """
        raise NotImplementedError

    async def sign_digest(self, digest: MessageDigest) -> Signature:
        """
        Sign a message that was already hashed.
        """
        raise NotImplementedError

    async def sign(self, msg: bytes) -> Signature:
        """
        Sign a message.
        """
        raise NotImplementedError

    def to_keyinfo_der(self, passphrase: Optional[bytes] = None) -> bytes:
        """
        Convert private key to PKCS#8 DER format.

        Args:
            passphrase: Optional passphrase to encrypt private key with.

        Returns:
            xxx encoded private key.
        """

        raise NotImplementedError

    def to_keyinfo_pem(self, passphrase: Optional[bytes] = None) -> str:
        """
        Convert private key to PKCS#8 PEM format.
        Output starts with ``-----BEGIN PRIVATE KEY-----``.

        Args:
            passphrase: Optional passphrase to encrypt private key with.

        Returns:
            xxx encoded private key.
        """

        raise NotImplementedError

    def to_openssl_der(self, passphrase: Optional[bytes] = None) -> bytes:
        """
        Convert private key to legacy/traditional openssl format. The result doesn't include information
        about what type of key was exported. If in doubt, use :py:meth:`to_keyinfo_der`.

        Same as e.g. ``openssl rsa -outform der``.

        Args:
            passphrase: Optional passphrase to encrypt private key with.

        Returns:
            xxx encoded private key.
        """

        raise NotImplementedError

    def to_openssl_pem(self, passphrase: Optional[bytes] = None) -> str:
        """
        Convert private key to legacy/traditional openssl format. The result includes information
        about what type of key was exported only in the PEM header, not in the contents.
        Output starts with ``-----BEGIN RSA PRIVATE KEY-----`` or similar.

        If in doubt, use :py:meth:`to_keyinfo_pem`.

        Same as e.g. ``openssl rsa -outform pem``.

        Args:
            passphrase: Optional passphrase to encrypt private key with.

        Returns:
            xxx encoded private key.
        """

        raise NotImplementedError

    def to_openssh_key_v1(self, passphrase: Optional[bytes] = None) -> bytes:
        """
        Convert private key to binary OpenSSH format as defined in `PROTOCOL.key
        <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key>`__.

        Args:
            passphrase: Optional passphrase to encrypt private key with.

        Returns:
            xxx encoded private key.
        """

        raise NotImplementedError

    def to_openssh_key_v1_pem(self, passphrase: Optional[bytes] = None) -> str:
        """
        Convert private key to OpenSSH format as defined in `PROTOCOL.key
        <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key>`__
        and format the result as PEM.
        Output starts with ``-----BEGIN OPENSSH PRIVATE KEY-----``.

        Same as e.g. ``ssh-keygen -p -m RFC4716``.

        Args:
            passphrase: Optional passphrase to encrypt private key with.

        Returns:
            xxx encoded private key.
        """

        raise NotImplementedError

    def to_jwk(self, fields: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        """
        Convert private key to a JSON Web Key as defined by :rfc:`rfc7517#section-4` and :rfc:`rfc7518#section-6`.

        Args:
            fields: Optional JWK fields to copy into the result, e.g. ``kid`` or ``alg``.

        Returns:
            Dictionary with ``kty`` and other members defined by that algorithm plus :py:obj:`fields`. Each call
            to this function returns a new object; it may be modified by the caller, e.g. to add more optional
            fields.
        """

        raise NotImplementedError

    # XXX validate function
    # XXX functions for decrypting (mind Bleichenbacher's padding oracle!) and DHKE.


@dataclass(frozen=True)
class SignatureMetadata:
    """
    Meta data for signatures. Extended by algorithm specific sub classes.
    """

    algorithm: AsymmetricAlgorithm


@dataclass(frozen=True)
class Signature:
    """
    Result of a sign operation.
    """

    # Public key part of the key that was used to create this signature.
    key: PublicKey = field(repr=False)

    # Meta data such as hash functions used.
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
