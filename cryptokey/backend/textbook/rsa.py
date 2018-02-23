"""
This module must not be used in real code.
The implementation is most likely suspectible to various side channel attacks.
In fact, it can serve as an example implementation to develop side channel exploits against, e.g.
for educational purposes.

If any change would improve the code quality (e.g. make it clearer) but introduce new
side channel attacks, the change should be implemented.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from functools import reduce
from operator import mul
from typing import Optional, Sequence, Tuple, Union

from asn1crypto import keys as asn1keys
from asn1crypto.pem import unarmor

from ...math import invert, lcm
from ...public.key import AsymmetricAlgorithm, PrivateKey, PublicKey
from ...public.rsa import RsaPrivateKey, RsaPublicKey, RsaScheme, RsaSignature, RsaSignatureMetadata
from ..partial.rsa import PartialRsaPrivateKey, PartialRsaPublicKey


@dataclass
class TextbookRsaPublicKey(PartialRsaPublicKey):
    exp: int
    mod: int

    @classmethod
    def from_key(cls, key: PublicKey) -> TextbookRsaPublicKey:
        if not isinstance(key, RsaPublicKey):
            raise TypeError()
        return cls(key.public_exponent, key.modulus)

    @property
    def public_exponent(self) -> int:
        """
        Public RSA exponent (e).
        """
        return self.exp

    @property
    def modulus(self) -> int:
        """
        RSA modulus (n).
        """
        return self.mod

    # def validate(self) -> None:
    #     pass

    # def verify(self, signature: Signature, message: bytes) -> None:
    #     if not isinstance(signature, RsaSignature):
    #         raise TypeError()

    # def verify_digest(self, signature: Signature, digest: MessageDigest) -> None:
    #     if not isinstance(signature, RsaSignature):
    #         raise TypeError()


@dataclass
class TextbookRsaPrivateKey(PartialRsaPrivateKey):
    public_exponent: InitVar[int]
    prime_factors: InitVar[Sequence[int]]
    _primes: Tuple[int, ...] = field(init=False)
    _modulus: int = field(init=False)
    _private_exponent: int = field(init=False)
    _public: TextbookRsaPublicKey = field(init=False)

    @classmethod
    def from_key(cls, key: PrivateKey) -> TextbookRsaPrivateKey:
        if not isinstance(key, RsaPrivateKey):
            raise TypeError()

        return cls(
            public_exponent=key.public.public_exponent,
            prime_factors=key.primes,
        )

    @classmethod
    def from_asn1crypto(cls, key: asn1keys.PrivateKeyInfo) -> TextbookRsaPrivateKey:
        if key.algorithm != 'rsa':
            raise ValueError()
        priv = key['private_key'].parsed
        # XXX load all other parts, implement CRT.
        return cls(
            public_exponent=priv['public_exponent'].native,
            prime_factors=(priv['prime1'].native, priv['prime2'].native),
        )

    @classmethod
    def load(
        cls,
        content: Union[str, bytes, asn1keys.PrivateKeyInfo],
        password: Optional[Union[str, bytes]] = None,
    ) -> TextbookRsaPrivateKey:
        """
        Load a private key from one of:

          * PKCS#8, PEM (str/bytes) or DER (bytes)
          * Traditional RSA (str/bytes), PEM or DER (bytes)
          * OpenSSH (XXX)
          * asn1crypto PrivateKeyInfo

        If key is encrypted, pass the decryption password.
        """

        if isinstance(content, asn1keys.PrivateKeyInfo):
            return cls.from_asn1crypto(content)

        if isinstance(content, str):
            content = content.encode()

        assert isinstance(content, bytes)

        if content.strip().startswith(b'-----BEGIN'):
            unarmor_result = unarmor(content)
            assert isinstance(unarmor_result, tuple)
            pem_type, headers, content = unarmor_result

        if content[0] == 0x30:
            key = asn1keys.PrivateKeyInfo.load(content)
            if key.dump(True) != content:
                raise ValueError()
            return cls.from_asn1crypto(key)

        raise TypeError()

    def __post_init__(self, public_exponent: int, prime_factors: Sequence[int]) -> None:
        if len(prime_factors) < 2:
            raise ValueError('Need at least 2 primes!')
        self._primes = tuple(prime_factors)
        self._modulus = reduce(mul, prime_factors, 1)

        # output of Carmichael function
        lambda_n = reduce(lcm, (r - 1 for r in prime_factors), 1)

        self._private_exponent = invert(public_exponent, lambda_n)
        # XXX implement CRT
        self._public = TextbookRsaPublicKey(public_exponent, self._modulus)

    @property
    def public(self) -> TextbookRsaPublicKey:
        """
        Get public key for this private key.
        """
        return self._public

    @property
    def primes(self) -> Sequence[int]:
        """
        Get list of primes. XXX describe order!
        """
        return self._primes

    @property
    def private_exponent(self) -> int:
        """
        Get private exponent.
        """
        return self._private_exponent

    async def sign_int(self, msg: int, meta: Optional[RsaSignatureMetadata] = None) -> RsaSignature:
        """
        Sign an integer value.
        """

        return RsaSignature(
            key=self._public,
            meta=meta or RsaSignatureMetadata(AsymmetricAlgorithm.RSA, RsaScheme.RAW),
            int_value=pow(msg, self._private_exponent, self._modulus),
        )

    # async def decrypt(self, ciphertext: bytes) -> bytes:
    #     raise NotImplementedError
