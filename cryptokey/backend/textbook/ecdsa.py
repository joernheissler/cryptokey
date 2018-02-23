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
from random import randint
from typing import Optional, Union

from asn1crypto import keys as asn1keys
from asn1crypto.pem import unarmor

from ... import hashes
from ...math import invert
from ...public import ecc, ecdsa
from ...public.key import AsymmetricAlgorithm, MessageDigest, PrivateKey, PublicKey
from ..hashlib import HashlibHash
from .ecc import Curve, CurvePoint, NeutralPoint, curve_map


@dataclass(frozen=False)
class TextbookEccPublicKey(ecdsa.EccPublicKey):
    p: InitVar[ecc.CurvePoint]
    _point: CurvePoint = field(init=False)

    def __post_init__(self, p: ecc.CurvePoint) -> None:
        self._point = p if isinstance(p, CurvePoint) else CurvePoint(p.curve_id, p.x, p.y)

    @property
    def point(self) -> CurvePoint:
        return self._point

    @classmethod
    def from_key(cls, key: PublicKey) -> TextbookEccPublicKey:
        """
        Create a backend key instance from another key.
        """
        if not isinstance(key, ecdsa.EccPublicKey):
            raise TypeError()

        return cls(key.point)

    # def encrypt(self, message: bytes) -> bytes:
    #     raise NotImplementedError()

    def export_public_der(self) -> bytes:
        raise NotImplementedError()

    def export_public_openssh(self) -> str:
        raise NotImplementedError()

    def export_public_pem(self) -> str:
        raise NotImplementedError()

    # def validate(self) -> None:
    #     raise NotImplementedError()

    # def verify(self, signature: Signature, message: bytes) -> None:
    #     raise NotImplementedError()

    # def verify_digest(self, signature: Signature, digest: MessageDigest) -> None:
    #     raise NotImplementedError()


@dataclass
class TextbookEccPrivateKey(ecdsa.EccPrivateKey):
    curve: Curve
    exp: int
    _public: TextbookEccPublicKey = field(init=False)

    def __post_init__(self) -> None:
        point = self.curve.gen * self.private_exponent
        if isinstance(point, NeutralPoint):
            raise ValueError('Bad exponent')
        self._public = TextbookEccPublicKey(point)

    @property
    def private_exponent(self) -> int:
        return self.exp

    @property
    def curve_id(self) -> ecc.CurveId:
        return self.curve.curve_id

    @classmethod
    def from_key(cls, key: PrivateKey) -> TextbookEccPrivateKey:
        """
        Create a backend key instance from another key.
        """
        if not isinstance(key, ecdsa.EccPrivateKey):
            raise TypeError()

        return cls(curve_map[key.curve_id], key.private_exponent)

    @classmethod
    def from_asn1crypto(cls, key: asn1keys.PrivateKeyInfo) -> TextbookEccPrivateKey:
        if key.algorithm != 'ec':
            raise TypeError()
        priv = key['private_key'].parsed
        return cls(
            # XXX support other curves
            curve=curve_map[ecc.CurveId.NIST_P_256],
            exp=priv['private_key'].native,
        )

    @classmethod
    def load(
        cls,
        content: Union[str, bytes, asn1keys.PrivateKeyInfo],
        password: Optional[Union[str, bytes]] = None,
    ) -> TextbookEccPrivateKey:
        """
        Load a private key from one of:

          * PKCS#8, PEM (str/bytes) or DER (bytes)
          * Traditional ECC (str/bytes), PEM or DER (bytes)
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
            return cls.from_asn1crypto(key)

        raise TypeError()

    # async def decrypt(self, ciphertext: bytes) -> bytes:
    #     raise NotImplementedError()

    def export_private_der(self) -> bytes:
        raise NotImplementedError()

    def export_private_openssh(self) -> str:
        raise NotImplementedError()

    def export_private_pem(self) -> str:
        raise NotImplementedError()

    @property
    def public(self) -> TextbookEccPublicKey:
        return self._public

    async def sign_dsa(
        self,
        msg: bytes,
        hash_alg: Optional[hashes.HashAlgorithm] = None,
        k: ecdsa.UniqueKeyParam = ecdsa.UniqueKey.DEFAULT,
    ) -> ecdsa.EcdsaSignature:
        dgst = HashlibHash.hash(hash_alg or self.default_hash_algorithm, msg)
        return await self.sign_digest_dsa(dgst, k)

    async def sign_digest_dsa(
        self,
        digest: MessageDigest,
        k: ecdsa.UniqueKeyParam = ecdsa.UniqueKey.DEFAULT,
    ) -> ecdsa.EcdsaSignature:
        q = self.curve.q

        if isinstance(k, ecdsa.UniqueKey):
            if k in {ecdsa.UniqueKey.DEFAULT, ecdsa.UniqueKey.RANDOM}:
                k = randint(1, q - 1)
            else:
                raise NotImplementedError()

        r = self.curve.gen * k
        if isinstance(r, NeutralPoint):
            raise Exception('Hit neutral point. Use a better k!')

        rx = r.x % q
        if not rx:
            raise Exception('Hit 0. Implement getting new k!!')

        s = (bits2int(digest.value, q) + self.private_exponent * rx) * invert(k, q) % q

        if not s:
            raise Exception('Hit 0. Implement getting new k!!')

        return ecdsa.EcdsaSignature(
            key=self.public,
            meta=ecdsa.EcdsaSignatureMetadata(AsymmetricAlgorithm.ECDSA, digest.algorithm),
            r=rx,
            s=s,
        )


def bits2int(value: bytes, q: int) -> int:
    return (int.from_bytes(value, 'big') >> max(0, (len(value) * 8 - q.bit_length()))) % q
