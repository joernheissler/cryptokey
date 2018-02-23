from __future__ import annotations

from typing import Optional, Sequence, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as cr_padding
from cryptography.hazmat.primitives.asymmetric import rsa as cr_rsa
from cryptography.hazmat.primitives.asymmetric import utils as cr_utils

from . import backend
from ...hashes import HashAlgorithm, MessageDigest
from ...padding import pss
from ...public import rsa
from ...public.key import AsymmetricAlgorithm, PrivateKey, PublicKey
from .hashes import create_hash


class RsaPublicKey(rsa.RsaPublicKey):
    def __init__(self, pubkey: cr_rsa.RSAPublicKey):
        self._pubkey = pubkey
        self._public_numbers = pubkey.public_numbers()

    @classmethod
    def from_key(cls, key: PublicKey) -> RsaPublicKey:
        if not isinstance(key, rsa.RsaPublicKey):
            raise TypeError()
        return cls(cr_rsa.RSAPublicNumbers(key.public_exponent, key.modulus).public_key(backend))

    @property
    def public_exponent(self) -> int:
        return self._public_numbers.e

    @property
    def modulus(self) -> int:
        return self._public_numbers.n

    def export_public_der(self) -> bytes:
        return self._pubkey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_public_pem(self) -> str:
        return self._pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def export_public_openssh(self) -> str:
        return self._pubkey.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode()

    # def validate(self) -> None:
    #     raise NotImplementedError()

    # def verify(self, signature: Signature, message: bytes) -> None:
    #     if not isinstance(signature, rsa.RsaSignature):
    #         raise TypeError()
    #     raise NotImplementedError()

    # def verify_digest(self, signature: Signature, digest: MessageDigest) -> None:
    #     if not isinstance(signature, rsa.RsaSignature):
    #         raise TypeError()
    #     raise NotImplementedError()

    # def encrypt(self, message: bytes) -> bytes:
    #     raise NotImplementedError()


class RsaPrivateKey(rsa.RsaPrivateKey):
    # These won't be implemented.
    sign_int = None
    sign_bytes = None
    sign_v15_raw = None

    def __init__(self, privkey: cr_rsa.RSAPrivateKey) -> None:
        self._privkey = privkey
        self._pubkey = RsaPublicKey(privkey.public_key())
        self._private_numbers = privkey.private_numbers()

    @classmethod
    def from_key(cls, key: PrivateKey) -> RsaPrivateKey:
        if not isinstance(key, rsa.RsaPrivateKey):
            raise TypeError()
        primes = key.primes
        if len(primes) < 2:
            raise ValueError('Need at least 2 primes')
        if len(primes) > 2:
            raise NotImplementedError('Cryptography does not support multi-prime RSA')

        exp = key.private_exponent
        return cls(cr_rsa.RSAPrivateNumbers(
            primes[1],  # XXX order of primes?
            primes[0],
            exp,
            cr_rsa.rsa_crt_dmp1(exp, primes[1]),
            cr_rsa.rsa_crt_dmq1(exp, primes[0]),
            cr_rsa.rsa_crt_iqmp(primes[1], primes[0]),
            RsaPublicKey.from_key(key.public)._public_numbers,
        ).private_key(backend))

    @property
    def public(self) -> RsaPublicKey:
        return self._pubkey

    @property
    def primes(self) -> Sequence[int]:
        """
        Primes, at least two. XXX q before p?
        """
        return self._private_numbers.q, self._private_numbers.p

    @property
    def private_exponent(self) -> int:
        return self._private_numbers.d

    def export_private_der(self) -> bytes:
        return self._privkey.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def export_private_pem(self) -> str:
        return self._privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def export_private_openssh(self) -> str:
        raise NotImplementedError()

    async def sign_digest(self, digest: MessageDigest) -> rsa.RsaSignature:
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

    # async def decrypt(self, ciphertext: bytes) -> bytes:
    #     raise NotImplementedError()

    async def sign_v15_digest(self, dgst: MessageDigest) -> rsa.RsaSignature:
        return self._sign_v15(dgst.value, dgst.algorithm, True)

    async def sign_v15(self, msg: bytes, hash_alg: Optional[HashAlgorithm] = None) -> rsa.RsaSignature:
        return self._sign_v15(msg, hash_alg or self.default_hash_algorithm, False)

    async def sign_pss_digest(self, dgst: MessageDigest, options: Optional[rsa.PssOptions] = None) -> rsa.RsaSignature:
        return self._sign_pss(dgst.value, options, dgst.algorithm)

    async def sign_pss(self, msg: bytes, options: Optional[rsa.PssOptions] = None) -> rsa.RsaSignature:
        return self._sign_pss(msg, options)

    def _sign_v15(self, data: bytes, hash_alg: HashAlgorithm, is_pre: bool) -> rsa.RsaSignature:
        h_alg = create_hash(hash_alg)

        return rsa.RsaSignature(
            key=self.public,
            bytes_value=self._privkey.sign(
                data,
                cr_padding.PKCS1v15(),
                cr_utils.Prehashed(h_alg) if is_pre else h_alg,
            ),
            meta=rsa.RsaV15Metadata(AsymmetricAlgorithm.RSA, rsa.RsaScheme.PKCS1v1_5, hash_alg),
        )

    def _sign_pss(self, data: bytes, options: Optional[rsa.PssOptions],
                  pre_hash_alg: Optional[HashAlgorithm] = None) -> rsa.RsaSignature:

        opt = options or self.default_pss_options
        hash_alg = opt and opt.hash_alg or self.default_hash_algorithm
        meta = pss.parse_pss_options(self.public, hash_alg, opt, pre_hash_alg)
        if meta.mgf_alg.algorithm_id != rsa.MgfAlgorithmId.MGF1:
            raise NotImplementedError(f'Unsupported algorithm: {meta.mgf_alg.algorithm_id}')
        if meta.trailer_field != b'\xbc':
            raise NotImplementedError('Only BC trailer supported')
        if options and options.salt is not None:
            raise NotImplementedError('Custom salt not supported')

        mgf1_hash_alg = cast(rsa.Mgf1Metadata, meta.mgf_alg).hash_alg

        h_alg = create_hash(meta.hash_alg)

        sig = self._privkey.sign(
            data,
            cr_padding.PSS(
                mgf=cr_padding.MGF1(create_hash(mgf1_hash_alg)),
                salt_length=meta.salt_length,
            ),
            cr_utils.Prehashed(h_alg) if pre_hash_alg else h_alg,
        )

        return rsa.RsaSignature(
            key=self.public,
            bytes_value=sig,
            meta=meta,
        )
