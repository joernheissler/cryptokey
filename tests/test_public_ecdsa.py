import pytest
from cryptokey.hashes import sha2_256
from cryptokey.public.ecdsa import EcdsaSignature, EcdsaSignatureMetadata
from cryptokey.public.key import AsymmetricAlgorithm


def test_signature() -> None:
    key = None
    meta = EcdsaSignatureMetadata(algorithm=AsymmetricAlgorithm.ECDSA, hash_alg=sha2_256())

    val_10_20 = b"\x30\x06\x02\x01\x0a\x02\x01\x14"

    sig0 = EcdsaSignature.create(key=key, meta=meta, der=val_10_20)
    assert sig0.r == 10
    assert sig0.s == 20

    sig1 = EcdsaSignature.create(key=key, meta=meta, r=10, s=20)
    assert sig0 == sig1

    with pytest.raises(ValueError, match="Bad parameters"):
        EcdsaSignature.create(key=key, meta=meta, der=val_10_20, r=10, s=20)
