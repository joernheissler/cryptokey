from __future__ import annotations

from typing import Optional

from asn1crypto import keys, pem

from ... import hashes
from ...padding import pss
from ...padding.v15 import enc_digestinfo, pad_pkcs1_v15
from ...public import key, rsa
from ..hashlib import HashlibHash


class PartialRsaPublicKey(rsa.RsaPublicKey):
    def export_public_der(self) -> bytes:
        return keys.PublicKeyInfo.wrap(
            keys.RSAPublicKey({
                'modulus': self.modulus,
                'public_exponent': self.public_exponent,
            }),
            'rsa',
        ).dump()

    def export_public_pem(self) -> str:
        return pem.armor("PUBLIC KEY", self.export_public_der()).decode()

    def export_public_openssh(self) -> str:
        raise NotImplementedError()


class PartialRsaPrivateKey(rsa.RsaPrivateKey):
    def export_private_der(self) -> bytes:
        raise NotImplementedError()

    def export_private_pem(self) -> str:
        raise NotImplementedError()

    def export_private_openssh(self) -> str:
        raise NotImplementedError()

    async def sign_int(self, msg: int, meta: Optional[rsa.RsaSignatureMetadata] = None) -> rsa.RsaSignature:
        if self.__class__.sign_bytes is PartialRsaPrivateKey.sign_bytes:
            raise NotImplementedError
        return await self.sign_bytes(rsa.i2osp(msg, self.public.modlen), meta)

    async def sign_bytes(self, msg: bytes, meta: Optional[rsa.RsaSignatureMetadata] = None) -> rsa.RsaSignature:
        if self.__class__.sign_int is PartialRsaPrivateKey.sign_int:
            raise NotImplementedError
        return await self.sign_int(rsa.os2ip(msg), meta)

    async def sign_v15_raw(self, msg: bytes, meta: Optional[rsa.RsaSignatureMetadata] = None) -> rsa.RsaSignature:
        return await self.sign_bytes(
            pad_pkcs1_v15(msg, self.public.modlen),
            meta or rsa.RsaSignatureMetadata(rsa.AsymmetricAlgorithm.RSA, rsa.RsaScheme.PKCS1v1_5_RAW),
        )

    async def sign_v15_digest(self, dgst: hashes.MessageDigest) -> rsa.RsaSignature:
        return await self.sign_v15_raw(
            enc_digestinfo(dgst),
            rsa.RsaV15Metadata(key.AsymmetricAlgorithm.RSA, rsa.RsaScheme.PKCS1v1_5, dgst.algorithm),
        )

    async def sign_v15(self, msg: bytes, hash_alg: Optional[hashes.HashAlgorithm] = None) -> rsa.RsaSignature:
        dgst = HashlibHash.hash(hash_alg or self.default_hash_algorithm, msg)
        return await self.sign_v15_digest(dgst)

    async def sign_pss_digest(self, dgst: hashes.MessageDigest,
                              options: Optional[rsa.PssOptions] = None) -> rsa.RsaSignature:
        opt = options or self.default_pss_options
        padded, meta = pss.pad_pss(self.public, self.default_hash_algorithm, dgst, opt)
        return await self.sign_bytes(padded, meta)

    async def sign_pss(self, msg: bytes, options: Optional[rsa.PssOptions] = None) -> rsa.RsaSignature:
        # 9.1.1/2)
        opt = options or self.default_pss_options
        hash_alg = opt and opt.hash_alg or self.default_hash_algorithm
        dgst = HashlibHash.hash(hash_alg, msg)
        return await self.sign_pss_digest(dgst, opt)

    async def sign_digest(self, digest: hashes.MessageDigest) -> rsa.RsaSignature:
        if self.default_scheme == rsa.RsaScheme.PSS:
            return await self.sign_pss_digest(digest)

        if self.default_scheme == rsa.RsaScheme.PKCS1v1_5:
            return await self.sign_v15_digest(digest)

        raise Exception(f'Bad default scheme: {self.default_scheme}')

    async def sign(self, msg: bytes) -> rsa.RsaSignature:
        if self.default_scheme == rsa.RsaScheme.PSS:
            return await self.sign_pss(msg)

        if self.default_scheme == rsa.RsaScheme.PKCS1v1_5:
            return await self.sign_v15(msg)

        raise Exception(f'Bad default scheme: {self.default_scheme}')
