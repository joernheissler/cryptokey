from typing import Optional, Union
from ...backends import Backend
from ..asymmetric import rsa


PrivateKey = Union[rsa.RSAPrivateKey]


class Encoding:
    PEM: str
    DER: str
    OpenSSH: str


class PrivateFormat:
    PKCS8: str
    TraditionalOpenSSL: str


class PublicFormat:
    SubjectPublicKeyInfo: str
    PKCS1: str
    OpenSSH: str


def load_pem_private_key(data: bytes, password: Optional[bytes], backend: Backend) -> PrivateKey: ...
