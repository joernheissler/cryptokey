"""
RSA backend for https://python-pkcs11.readthedocs.io/en/latest/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

import pkcs11

from ...public.key import AsymmetricAlgorithm, PrivateKey, PublicKey
from ...public.rsa import RsaScheme, RsaSignature, RsaSignatureMetadata, os2ip
from ..partial.rsa import PartialRsaPrivateKey, PartialRsaPublicKey


@dataclass
class Pkcs11RsaPublicKey(PartialRsaPublicKey):
    """
    PKCS#11 RSA Public Key
    """
    # "private" is okay for now
    key: pkcs11.types.PrivateKey

    @classmethod
    def from_key(cls, key: PublicKey) -> Pkcs11RsaPublicKey:
        raise NotImplementedError('Not supported')

    @property
    def public_exponent(self) -> int:
        """
        Public RSA exponent (e).
        """
        return os2ip(self.key[pkcs11.Attribute.PUBLIC_EXPONENT])

    @property
    def modulus(self) -> int:
        """
        RSA modulus (n).
        """
        return os2ip(self.key[pkcs11.Attribute.MODULUS])


@dataclass
class Pkcs11RsaPrivateKey(PartialRsaPrivateKey):
    """
    PKCS#11 RSA Private Key
    """
    key: pkcs11.types.PrivateKey
    _pub: Pkcs11RsaPublicKey = field(init=False)
    default_scheme: RsaScheme = RsaScheme.PKCS1v1_5

    def __post_init__(self) -> None:
        self._pub = Pkcs11RsaPublicKey(self.key)

    @classmethod
    def from_key(cls, key: PrivateKey) -> Pkcs11RsaPrivateKey:
        raise NotImplementedError('Not supported')

    @property
    def public(self) -> Pkcs11RsaPublicKey:
        """
        Get public key for this private key.
        """
        return self._pub

    async def sign_v15_raw(self, msg: bytes, meta: Optional[RsaSignatureMetadata] = None) -> RsaSignature:
        """
        Sign raw value that is not yet v15 padded.
        """
        return RsaSignature(
            key=self._pub,
            meta=meta or RsaSignatureMetadata(AsymmetricAlgorithm.RSA, RsaScheme.PKCS1v1_5_RAW),
            bytes_value=self.key.sign(msg, mechanism=pkcs11.Mechanism.RSA_PKCS),
        )

    @property
    def private_exponent(self) -> int:
        raise NotImplementedError('Not supported')

    @property
    def primes(self) -> Sequence[int]:
        raise NotImplementedError('Not supported')
