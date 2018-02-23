from asyncio import run
from base64 import b64decode
from typing import Optional

import pytest
from cryptokey import hashes
from cryptokey.backend.hashlib import md5
from cryptokey.backend.partial.rsa import (PartialRsaPrivateKey,
                                           PartialRsaPublicKey)
from cryptokey.public import rsa

pub64 = 'MEkwDQYJKoZIhvcNAQEBBQADOAAwNQIuANWNl1uwOSG5brFOIZXGlcv2JWt1ATU/bGZLXK2vkz1E4CA0Uf/kMIYeJFIcYwIDAQAB'


class DummyPublicKey(PartialRsaPublicKey):
    from_key = None
    modulus = 0xd58d975bb03921b96eb14e2195c695cbf6256b7501353f6c664b5cadaf933d44e0203451ffe430861e24521c63
    public_exponent = 0x10001


class DummyPrivateKey(PartialRsaPrivateKey):
    from_key = None
    primes = 0xe147c05d8bac5364615b1aa16313d25576200de10664f, 0xf2ac756440151550d7e783e44724997ee1f9c701e37ad
    private_exponent = 0x480506649f9bc4e9da90e53ea25a64ae7286d0249791a9c2fb2320b783da8d4f5144a89f14b0b155c5757266f1
    public = DummyPublicKey()
    sig_meta = None


class SignV15PrivateKey(DummyPrivateKey):
    default_scheme = rsa.RsaScheme.PKCS1v1_5

    async def sign_v15_digest(self, dgst: hashes.MessageDigest) -> rsa.RsaSignature:
        raise Exception('sign_v15_digest called')


class SignIntPrivateKey(DummyPrivateKey):
    async def sign_int(self, msg: int, meta: Optional[rsa.RsaSignatureMetadata] = None) -> rsa.RsaSignature:
        raise Exception('sign_int called')


class SignBytesPrivateKey(DummyPrivateKey):
    async def sign_bytes(self, msg: bytes, meta: Optional[rsa.RsaSignatureMetadata] = None) -> rsa.RsaSignature:
        raise Exception('sign_bytes called')


def test_exports() -> None:
    priv = DummyPrivateKey()
    with pytest.raises(NotImplementedError):
        priv.export_private_der()
    with pytest.raises(NotImplementedError):
        priv.export_private_pem()
    with pytest.raises(NotImplementedError):
        priv.export_private_openssh()

    pub = priv.public
    with pytest.raises(NotImplementedError):
        pub.export_public_openssh()

    assert pub.export_public_der() == b64decode(pub64)

    pub_lines = pub.export_public_pem().splitlines()
    assert pub_lines[0] == '-----BEGIN PUBLIC KEY-----'
    assert pub_lines[-1] == '-----END PUBLIC KEY-----'
    assert ''.join(pub_lines[1:-1]) == pub64


def test_sign_loop() -> None:
    priv = DummyPrivateKey()
    with pytest.raises(NotImplementedError):
        run(priv.sign_int(12345))
    with pytest.raises(NotImplementedError):
        run(priv.sign_bytes(b'foo'))


def test_sign_int() -> None:
    key = SignIntPrivateKey()
    with pytest.raises(Exception, match='sign_int called'):
        run(key.sign_int(12345))
    with pytest.raises(Exception, match='sign_int called'):
        run(key.sign_bytes(b'foo'))
    with pytest.raises(Exception, match='sign_int called'):
        run(key.sign_v15(b'foo', hashes.md5()))


def test_sign_bytes() -> None:
    key = SignBytesPrivateKey()
    with pytest.raises(Exception, match='sign_bytes called'):
        run(key.sign_int(12345))
    with pytest.raises(Exception, match='sign_bytes called'):
        run(key.sign_bytes(b'foo'))


def test_no_pss() -> None:
    key = SignV15PrivateKey()
    with pytest.raises(Exception, match='sign_v15_digest called'):
        run(key.sign(b'foo'))
    with pytest.raises(Exception, match='sign_v15_digest called'):
        run(key.sign_digest(md5(b'foo')))
