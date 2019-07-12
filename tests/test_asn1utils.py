from asyncio import run

from asn1crypto.core import PrintableString, UTF8String
from cryptography import x509
from cryptokey.asn1utils import build_csr
from cryptokey.backend.cryptography import backend
from cryptokey.backend.textbook import ecc, ecdsa, rsa


def test_build_csr() -> None:
    for key in [
        ecdsa.TextbookEccPrivateKey(ecc.NIST_P_256, 12345),
        rsa.TextbookRsaPrivateKey(65537, [2 ** 521 - 1, 2 ** 607 - 1]),
    ]:
        subject = [("country_name", PrintableString("QY")), ("common_name", UTF8String("cryptokey"))]
        csr = run(build_csr(key, subject))
        req = x509.load_der_x509_csr(csr, backend)
        assert req.is_signature_valid
        assert req.subject.rfc4514_string() == "C=QY,CN=cryptokey"
