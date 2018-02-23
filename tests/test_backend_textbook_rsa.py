from asyncio import run
from base64 import b64decode
from os import urandom

import pytest
from asn1crypto.keys import PrivateKeyInfo
from cryptokey import hashes
from cryptokey.backend.hashlib import md5, sha2_256
from cryptokey.backend.textbook.rsa import (TextbookRsaPrivateKey,
                                            TextbookRsaPublicKey)
from cryptokey.public import rsa
from cryptokey.public.key import AsymmetricAlgorithm

key_pem = '''
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQClu6dYuI7wSz4p
4SFtMZmnHw/T/BBYnOVqNoj7rY9AwZ4E52PXdE4uj3UFymsu84uCnbK5yeq9IErC
YDwX4Omu7G7lsQMx44HPKG4j+iwVSOgXlhWG276W7iosjUuVLO8uQfTjk9tXv3Cg
zdQ4sEu64ltDOIapRXQiOZBJgs7Cc2RygVpb8mWJeWT8cPDmVNoTUkgJBr7dkbIf
XM6R4nnrzBPr5FfzrWK90m1ClnSyR/46i8OAw75khPJw97MO3fYpG8jf1HIsatKh
zzu2taxIKyi5hxyS59lkiDQIk218Q1lBG5+zKgDhIQ6IF+Tm6zFzKoEDZhY6CCjD
p6r6neQdAgMBAAECggEAJP1L7VZLuL/iYPB5SGiwlYcuPi7c6xohbeI8Eof7GAXe
odOPChBQPr4P7TnvUCxVL9LIiATT2mAxr05ROzcckMj+O0+VmfXgC/9HDcqROjLq
chEyPsYetIr1aLoka2f6/gUEhiKC6wO0PH+T5Q8b59sLaWZdT7xLnjPgyzdhtC43
A6EwfbXWBtE4Dt8Y64hdY2zk/YOI7jhJSA9aaFf05FuxY/XNYfMkOA+6kDrrdsNN
25wiG3FlxKpSe8CAGBG4oB5+tTQeMHqZEH0/TfIAnlJvA51gsHaq4SCoJMeakCwR
Kj09M7a84GiXJK9LoBkbI3m3HOKq8wdTbe1Hf5dIwQKBgQDPI5p60Y/oeHwnO1Al
CvFYD8v/kdHuqjLoWh6cpBAk6cskhpnm0W+UHH/IODHb1cs+BcbUV1P2Ne7b52fZ
/a73Ax7bgeIayGeUVYpiynIitArHFeWxJVFuKx7eOmCmtqfhKMO8FmJYjWxwbQv2
/mAJ7r9IesG6cHCkpRHNq4o3rQKBgQDM069fZL/8+eZizebZ6t91ItSYwdM7hsfK
aXgwJivZnTM48dPX20wRd18qRAAtOvLymHXLsWZhN6IXeyz3CbItuUOjSWuEe4n2
m9O4BBiT85ksakUgfODCxbJ4hYR4H1QSs4r8pBRJtZFgbJkBrbl1z3yo8BT8bM9A
ZniBouWsMQKBgQCIR9ZlI+dYfZzBewaZuH9c/teqh9fk/FmOAWzOhiqQ/rjGiUBM
WlLc0XtI0aAMELctUUOlhOcawBUs3Sy4gW1R2t28cdG+6UcskrL/mE5LgsTsgv2h
9PmEUB54+1OHm/kL7HQLFXcS58kGltgeYvHw1wFGwG0hKsURrgDungPL6QKBgQDE
NqEQdBZKxCZETlSwOwSXVKduMnck1gd8Sq7dCSQGkkXobhju9mAXd1AN0BiPO6JS
bWSina2iwcWgUtoPSRWMIaa+vG2n+yR9vmcCJ8JXsQrx9leEOLyjOPmv5M+ytug2
BhLF1HSu66V5Rm8IoaBBUGNt/pdL/PxJCCC2pxL3cQKBgGMtUJ598XbYhlSGD3x2
59u4dGO30wVMk7UwpuU5QRaQozSEBSQOyA3AyNIjIiLWyn0tKfx5RAtkQmOXF55H
S0Gn3l6ko3L/EJ2eYmUbVU6LKyQCGqiHSOsNc1ZguNj+PBNRmYayUADEx4p8KWis
0VFPLGLLPtyUaP2eQx1qFynj
-----END PRIVATE KEY-----
'''
key = TextbookRsaPrivateKey.load(key_pem)
public = key.public

pub64 = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApbunWLiO8Es+KeEhbTGZpx8P0/wQWJzlajaI+62PQMGeBOdj13ROLo'
    '91BcprLvOLgp2yucnqvSBKwmA8F+Dpruxu5bEDMeOBzyhuI/osFUjoF5YVhtu+lu4qLI1LlSzvLkH045PbV79woM3UOLBLuuJb'
    'QziGqUV0IjmQSYLOwnNkcoFaW/JliXlk/HDw5lTaE1JICQa+3ZGyH1zOkeJ568wT6+RX861ivdJtQpZ0skf+OovDgMO+ZITycP'
    'ezDt32KRvI39RyLGrSoc87trWsSCsouYcckufZZIg0CJNtfENZQRufsyoA4SEOiBfk5usxcyqBA2YWOggow6eq+p3kHQIDAQAB'
)


def test_public_from_key() -> None:
    pub = TextbookRsaPublicKey.from_key(public)
    assert pub is not public
    assert pub.public_exponent == public.public_exponent
    assert pub.modulus == public.modulus

    with pytest.raises(TypeError):
        TextbookRsaPublicKey.from_key('p=17, q=23, e=3')  # type: ignore


def test_public_exponent() -> None:
    assert public.public_exponent == 65537


def test_public_modulus() -> None:
    assert public.modulus % 1234567 == 218930


def test_public_export_der() -> None:
    assert public.export_public_der() == b64decode(pub64)


def test_public_export_pem() -> None:
    lines = public.export_public_pem().splitlines()
    assert lines[0] == '-----BEGIN PUBLIC KEY-----'
    assert lines[-1] == '-----END PUBLIC KEY-----'
    assert ''.join(lines[1:-1]) == pub64


def test_private_from_key() -> None:
    priv = TextbookRsaPrivateKey.from_key(key)
    assert priv is not key
    assert sorted(priv.primes) == sorted(key.primes)
    assert priv.private_exponent == key.private_exponent

    with pytest.raises(TypeError):
        TextbookRsaPrivateKey.from_key('test')  # type: ignore


def test_load() -> None:
    # not RSA
    with pytest.raises(ValueError):
        TextbookRsaPrivateKey.load(b'''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCaUaXQQho8ZJzBxW
GAUaaZYXpCrAIkTGQ4SNFPgc8a6hRANCAARuhfAJsHe80Rqp5wI4IxhM8QDk5CgV
eQcGofFqXjiWpch0OAKBQTbCqdvAnmXzG2rqfA4sJNwGIIi6xXfZxQEn
-----END PRIVATE KEY-----
        ''')

    key_der = b64decode(''.join(key_pem.strip().splitlines()[1:-1]))
    pki = PrivateKeyInfo.load(key_der)
    k0 = TextbookRsaPrivateKey.load(pki)
    k1 = TextbookRsaPrivateKey.load(key_pem)
    k2 = TextbookRsaPrivateKey.load(key_der)

    assert k0.private_exponent == key.private_exponent
    assert k1.private_exponent == key.private_exponent
    assert k2.private_exponent == key.private_exponent

    # public exponent is encoded as "00 01 00 01", i.e. bad leading zero.
    with pytest.raises(ValueError):
        TextbookRsaPrivateKey.load(b64decode('''
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA6cwdAA4K/x7+sHX5TS+rNtM/v3hDr+sdQr3Bbl0JCwKH
yiWpVKt6fsKFCfsBD/Zvfe++Ot+GAAe/M2r2mN660QIEAAEAAQJAfERjfa35JlVBJmXuVppptMBf99NiltSvPtRBRfnp
XpG7j6JFwAsAyKcsAFo4ZXMj3K71GLLVRXKNVArRSuwj4QIhAPwAaunIMWjw/wWA/I0vIqKf/i18DFe0Pv8q+SM54Ipl
AiEA7YHA0rpJLQ6JIGHG/ZL9F8GKXtFf6sjlszYzBli8Uf0CIQDlFZgbiELqjFK49SYhTp0ky18siB1MSW4PV0h+rmmi
RQIgExHN9515bqKyI+V14rpAk/24LHDHMMS8nK0HX8UUKckCIENRTBNmauD1vtBqstLj456t712kYvV3MFunRbc6hR7C
        '''))

    with pytest.raises(TypeError):
        TextbookRsaPrivateKey.load('Hello')


def test_init() -> None:
    with pytest.raises(ValueError):
        TextbookRsaPrivateKey(65537, [31])


def test_sign_v15() -> None:
    key.default_hash_algorithm = hashes.sha2_256()

    sig0 = run(key.sign_v15(b'Hello'))
    sig1 = run(key.sign_v15_digest(sha2_256(b'Hello')))
    assert sig0 == sig1
    assert sig0.algorithm == AsymmetricAlgorithm.RSA
    assert sig0.meta == rsa.RsaV15Metadata(AsymmetricAlgorithm.RSA, rsa.RsaScheme.PKCS1v1_5, hashes.sha2_256())
    assert sig0.meta == sig1.meta

    key.default_hash_algorithm = hashes.md5()
    sig2 = run(key.sign_v15(b'Hello'))
    sig3 = run(key.sign_v15_digest(md5(b'Hello')))
    assert sig2 == sig3
    assert sig2.algorithm == AsymmetricAlgorithm.RSA
    assert sig2.meta == rsa.RsaV15Metadata(AsymmetricAlgorithm.RSA, rsa.RsaScheme.PKCS1v1_5, hashes.md5())
    assert sig2.meta == sig3.meta

    sig4 = run(key.sign_v15(b'Hello', hashes.sha2_256()))
    assert sig0 == sig4


def test_sign_pss() -> None:
    key.default_hash_algorithm = hashes.sha2_256()
    key.default_pss_options = None

    opt = rsa.PssOptions(salt=urandom(123))
    sig0 = run(key.sign_pss(b'Hello', opt))
    sig1 = run(key.sign_pss_digest(sha2_256(b'Hello'), opt))
    assert sig0 == sig1
    assert sig0.algorithm == AsymmetricAlgorithm.RSA
    assert sig0.meta == rsa.RsaPssMetadata(AsymmetricAlgorithm.RSA, rsa.RsaScheme.PSS, hashes.sha2_256(),
                                           rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.sha2_256()), 123, b'\xbc')


def test_sign() -> None:
    key.default_scheme = rsa.RsaScheme.PKCS1v1_5
    key.default_hash_algorithm = hashes.sha2_256()
    meta = key.sig_meta

    sig0 = run(key.sign(b'Hello'))
    assert sig0.algorithm == AsymmetricAlgorithm.RSA
    assert sig0.meta == meta

    sig1 = run(key.sign_digest(sha2_256(b'Hello')))
    assert sig1.algorithm == AsymmetricAlgorithm.RSA
    assert sig1.meta == meta

    key.default_hash_algorithm = hashes.md5()
    sig2 = run(key.sign_digest(sha2_256(b'Hello')))
    assert sig2.meta == rsa.RsaV15Metadata(AsymmetricAlgorithm.RSA, rsa.RsaScheme.PKCS1v1_5, hashes.sha2_256())
    assert sig2.meta == meta

    key.default_scheme = rsa.RsaScheme.PSS
    key.default_pss_options = rsa.PssOptions(trailer_field=b'foobar', salt_length=17)
    meta_pss = key.sig_meta
    sig3 = run(key.sign(b'Hello'))
    assert sig3.meta == meta_pss
    assert meta_pss == rsa.RsaPssMetadata(AsymmetricAlgorithm.RSA, rsa.RsaScheme.PSS, hashes.md5(),
                                          rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.md5()), 17, b'foobar')

    sig4 = run(key.sign_digest(md5(b'Hello')))
    assert sig4.meta == meta_pss

    key.default_scheme = rsa.RsaScheme.RAW
    with pytest.raises(Exception, match='Bad default scheme'):
        run(key.sign(b'foo'))
    with pytest.raises(Exception, match='Bad default scheme'):
        run(key.sign_digest(md5(b'foo')))
    with pytest.raises(Exception, match='Unsupported scheme'):
        key.sig_meta
