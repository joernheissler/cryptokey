from asyncio import run
from base64 import b64decode

import pytest
from asn1crypto.keys import PrivateKeyInfo
from cryptokey import hashes
from cryptokey.backend.hashlib import sha2_256
from cryptokey.backend.textbook import ecc, ecdsa
from cryptokey.public.ecc import CurveId
from cryptokey.public.ecdsa import EcdsaSignatureMetadata, UniqueKey
from cryptokey.public.key import AsymmetricAlgorithm

# FIPS_186-3 test vector
msg = bytes.fromhex(
    '5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf'
    '416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5'
    '473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17c'
    'c934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8'
)
key_d = 0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464
sig_k = 0x94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de
sig_r = 0xf3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac
sig_s = 0x8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903
key = ecdsa.TextbookEccPrivateKey(ecc.NIST_P_256, key_d)
pub = key.public

key_pem = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUZtCPXFfi1gfT6ju
WfR3GltEyBMLTj6sylSlbdpytGShRANCAAQcy+kcB1/H9PAzv6JI24/M01Zd6Uu/
sS88Wf9GwnG/g85AFMaIEfmiGh/bLA5hE+Btt8qTt0BOeNx8zVyomkyp
-----END PRIVATE KEY-----
'''


def test_public_from_key() -> None:
    assert ecdsa.TextbookEccPublicKey.from_key(pub) == pub
    with pytest.raises(TypeError):
        ecdsa.TextbookEccPublicKey.from_key(b'foo')  # type: ignore


def test_public_export() -> None:
    with pytest.raises(NotImplementedError):
        pub.export_public_der()
    with pytest.raises(NotImplementedError):
        pub.export_public_pem()
    with pytest.raises(NotImplementedError):
        pub.export_public_openssh()


def test_private_init() -> None:
    with pytest.raises(ValueError, match='exponent'):
        ecdsa.TextbookEccPrivateKey(ecc.NIST_P_256, ecc.NIST_P_256.q)


def test_private_exp() -> None:
    assert key.private_exponent == key_d


def test_private_curve_id() -> None:
    assert key.curve_id == CurveId.NIST_P_256


def test_private_from_key() -> None:
    with pytest.raises(TypeError):
        ecdsa.TextbookEccPrivateKey.from_key(b'foo')  # type: ignore

    assert ecdsa.TextbookEccPrivateKey.from_key(key) == key


def test_private_load() -> None:
    with pytest.raises(TypeError):
        ecdsa.TextbookEccPrivateKey.load(b64decode(
            'MEECAQAwDQYJKoZIhvcNAQEBBQAELTArAgEAAgUAmUvqJQIDAQABAgRIRJAtAgMAyFcCAwDD4wICAkcCAlmJAgIuOA=='
        ))

    with pytest.raises(TypeError):
        ecdsa.TextbookEccPrivateKey.load('Hello')

    key_der = b64decode(''.join(key_pem.strip().splitlines()[1:-1]))
    pki = PrivateKeyInfo.load(key_der)
    k0 = ecdsa.TextbookEccPrivateKey.load(pki)
    k1 = ecdsa.TextbookEccPrivateKey.load(key_pem)
    k2 = ecdsa.TextbookEccPrivateKey.load(key_der)

    assert k0 == key
    assert k1 == key
    assert k2 == key

    assert ecdsa.TextbookEccPrivateKey(ecc.NIST_P_256, 12345) != key


def test_private_export() -> None:
    with pytest.raises(NotImplementedError):
        key.export_private_der()
    with pytest.raises(NotImplementedError):
        key.export_private_pem()
    with pytest.raises(NotImplementedError):
        key.export_private_openssh()


def test_sign_dsa() -> None:
    sig = run(key.sign_dsa(msg, hashes.sha2_256(), sig_k))
    assert sig.key == key.public
    assert sig.r == sig_r
    assert sig.s == sig_s

    meta = key.sig_meta
    assert meta == EcdsaSignatureMetadata(AsymmetricAlgorithm.ECDSA, hashes.sha2_256())

    sig2 = run(key.sign(msg))
    assert sig2.key == key.public
    assert sig2.r and sig2.s  # XXX verify the values
    assert sig2.meta == meta

    sig3 = run(key.sign_digest(sha2_256(msg)))
    assert sig3.key == key.public
    assert sig3.r and sig3.s  # XXX verify the values
    assert sig3.meta == meta

    key.default_hash_algorithm = hashes.md5()
    sig4 = run(key.sign(msg))
    assert sig4.meta == EcdsaSignatureMetadata(AsymmetricAlgorithm.ECDSA, hashes.md5())

    with pytest.raises(NotImplementedError):
        run(key.sign_dsa(msg, hashes.sha2_256(), UniqueKey.RFC6979))

    with pytest.raises(Exception, match='neutral point'):
        run(key.sign_dsa(msg, hashes.sha2_256(), ecc.NIST_P_256.q))
