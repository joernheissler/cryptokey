from __future__ import annotations

from typing import ByteString, Optional

import pytest
from cryptokey import hashes
from cryptokey.oid import OID

algos_test_data = [
    (hashes.blake2b(20), "BLAKE2B", hashes.Blake2Params(20), 20, "1.3.6.1.4.1.1722.12.2.1.5"),
    (hashes.blake2s(20), "BLAKE2S", hashes.Blake2Params(20), 20, "1.3.6.1.4.1.1722.12.2.2.5"),
    (hashes.md5(), "MD5", None, 16, "1.2.840.113549.2.5"),
    (hashes.ripemd_160(), "RIPEMD_160", None, 20, "1.3.36.3.2.1"),
    (hashes.sha1(), "SHA1", None, 20, "1.3.14.3.2.26"),
    (hashes.sha2_224(), "SHA2_224", None, 28, "2.16.840.1.101.3.4.2.4"),
    (hashes.sha2_256(), "SHA2_256", None, 32, "2.16.840.1.101.3.4.2.1"),
    (hashes.sha2_384(), "SHA2_384", None, 48, "2.16.840.1.101.3.4.2.2"),
    (hashes.sha2_512(), "SHA2_512", None, 64, "2.16.840.1.101.3.4.2.3"),
    (hashes.sha2_512_224(), "SHA2_512_224", None, 28, "2.16.840.1.101.3.4.2.5"),
    (hashes.sha2_512_256(), "SHA2_512_256", None, 32, "2.16.840.1.101.3.4.2.6"),
    (hashes.sha3_224(), "SHA3_224", None, 28, "2.16.840.1.101.3.4.2.7"),
    (hashes.sha3_256(), "SHA3_256", None, 32, "2.16.840.1.101.3.4.2.8"),
    (hashes.sha3_384(), "SHA3_384", None, 48, "2.16.840.1.101.3.4.2.9"),
    (hashes.sha3_512(), "SHA3_512", None, 64, "2.16.840.1.101.3.4.2.10"),
    (hashes.shake_128(), "SHAKE_128", None, 16, "2.16.840.1.101.3.4.2.11"),
    (hashes.shake_128_len(12), "SHAKE_128_LEN", hashes.ShakeLenParams(12), 12, "2.16.840.1.101.3.4.2.17"),
    (hashes.shake_256(), "SHAKE_256", None, 32, "2.16.840.1.101.3.4.2.12"),
    (hashes.shake_256_len(12), "SHAKE_256_LEN", hashes.ShakeLenParams(12), 12, "2.16.840.1.101.3.4.2.18"),
]


@pytest.mark.parametrize("alg,algorithm_id,parameters,size,oid", algos_test_data)
def test_algos(
    alg: hashes.HashAlgorithm,
    algorithm_id: str,
    parameters: Optional[hashes.HashParameters],
    size: int,
    oid: str,
) -> None:
    assert alg.algorithm_id == hashes.HashAlgorithmId[algorithm_id]
    assert alg.parameters == parameters
    assert alg.size == size
    assert alg.oid == OID(oid)


def test_blake2() -> None:
    with pytest.raises(ValueError, match="multiples of 32 bit"):
        hashes.blake2b(17).oid
    with pytest.raises(ValueError, match="multiples of 32 bit"):
        hashes.blake2s(17).oid


def test_dummy() -> None:
    alg = hashes.HashAlgorithm(hashes.HashAlgorithmId._TEST_DUMMY)
    with pytest.raises(ValueError, match="No OID defined"):
        alg.oid


class HashFunctionImpl(hashes.HashFunction):
    def _finalize(self) -> bytes:
        return b"x" * self.algorithm.size

    def copy(self) -> HashFunctionImpl:
        return self

    def update(self, data: ByteString) -> HashFunctionImpl:
        return self


def test_hash_function() -> None:
    assert HashFunctionImpl.hash(hashes.sha3_224(), b"foo").value == b"x" * 28
    assert HashFunctionImpl.load_digest(hashes.sha3_224(), b"q" * 28).value == b"q" * 28

    func = HashFunctionImpl(hashes.sha2_512())
    func.update(b"foo")
    assert func.finalize().value == b"x" * 64
    assert func.finalize().value == b"x" * 64
    assert func.oid == OID("2.16.840.1.101.3.4.2.3")
    assert func.size == 64
    assert func.copy() is func


def test_digest() -> None:
    dig = HashFunctionImpl.hash(hashes.sha2_512(), b"foo")
    new = dig.new()
    assert isinstance(new, HashFunctionImpl)
    assert new.algorithm == hashes.sha2_512()
    assert dig.oid == OID("2.16.840.1.101.3.4.2.3")
    assert dig.size == 64
    assert dig.hexvalue == "78" * 64
    assert bytes(dig) == b"x" * 64
    assert len(dig) == 64

    func = HashFunctionImpl(hashes.sha2_512())
    with pytest.raises(ValueError, match="Digest size must be"):
        hashes.MessageDigest.create(b"hash", func)
