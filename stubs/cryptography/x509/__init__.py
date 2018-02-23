from ..hazmat.backends import Backend


class NameAttribute:
    def rfc4514_string(self) -> str: ...


class CertificateSigningRequest:
    def is_signature_valid(self) -> bool: ...
    @property
    def subject(self) -> NameAttribute: ...


def load_der_x509_csr(data: bytes, backend: Backend) -> CertificateSigningRequest: ...
