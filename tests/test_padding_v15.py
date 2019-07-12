import pytest
from cryptokey.backend.hashlib import HashlibHash
from cryptokey.hashes import HashAlgorithm, HashAlgorithmId
from cryptokey.padding.v15 import enc_digestinfo, pad_pkcs1_v15


def test_enc_di() -> None:
    # See https://tools.ietf.org/html/rfc8017#section-9.2 note 1

    paddings = {
        HashAlgorithmId.MD5: "3020300c06082a864886f70d020505000410",
        HashAlgorithmId.SHA1: "3021300906052b0e03021a05000414",
        HashAlgorithmId.SHA2_224: "302d300d06096086480165030402040500041c",
        HashAlgorithmId.SHA2_256: "3031300d060960864801650304020105000420",
        HashAlgorithmId.SHA2_384: "3041300d060960864801650304020205000430",
        HashAlgorithmId.SHA2_512: "3051300d060960864801650304020305000440",
        HashAlgorithmId.SHA2_512_224: "302d300d06096086480165030402050500041c",
        HashAlgorithmId.SHA2_512_256: "3031300d060960864801650304020605000420",
    }

    for alg, pad in paddings.items():
        dgst = HashlibHash.hash(HashAlgorithm(alg), b"foo")
        assert enc_digestinfo(dgst) == bytes.fromhex(pad) + dgst.value


def test_pad() -> None:
    with pytest.raises(ValueError):
        pad_pkcs1_v15(b"foo", 13)

    assert pad_pkcs1_v15(b"foo", 14) == b"\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00foo"
    assert pad_pkcs1_v15(b"foo", 15) == b"\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00foo"
