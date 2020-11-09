from asyncio import run

import pytest
from cryptokey import hashes
from cryptokey.public import rsa
from cryptokey.public.key import AsymmetricAlgorithm

int_vectors = [
    (0, b""),
    (1, b"\x01"),
    (127, b"\x7f"),
    (128, b"\x80"),
    (129, b"\x81"),
    (255, b"\xff"),
    (256, b"\x01\x00"),
    (257, b"\x01\x01"),
    (258, b"\x01\x02"),
    (511, b"\x01\xff"),
    (512, b"\x02\x00"),
    (31337, b"\x7a\x69"),
    (
        int(
            "3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067"
            "9821480865132823066470938446095505822317253594081284811174502841027019385211055596446229489549303819"
            "6442881097566593344612847564823378678316527120190914564856692346034861045432664821339360726024914127"
            "3724587006606315588174881520920962829254091715364367892590360011330530548820466521384146951941511609"
            "4330572703657595919530921861173819326117931051185480744623799627495673518857527248912279381830119491"
            "2983367336244065664308602139494639522473719070217986094370277053921717629317675238467481846766940513"
            "2000568127145263560827785771342757789609173637178721468440901224953430146549585371050792279689258923"
            "5420199561121290219608640344181598136297747713099605187072113499999983729780499510597317328160963185"
            "9502445945534690830264252230825334468503526193118817101000313783875288658753320838142061717766914730"
            "3598253490428755468731159562863882353787593751957781857780532171226806613001927876611195909216420198"
        ),
        bytes.fromhex(
            "01320ef0126ef9258b2f5731dfef4b62d6ce390f70f10e098d8a8e980746de37a02403b7eb2c88a615897fc11ea14a7f1d335a38"
            "1f1bd84dce8f0bab1ff49375891b2ea2649c49d950dd466847475fde63b6d45fef5055ab4a1fbf5884551a12a8a9b83e56509439"
            "eec43e54ed93d5c65d6b5a02f5472ab24f1063656353a118d8e455c22fbd0c7dc2e66a37bda0314ae5da239e7c740c269ee2f129"
            "5be9d6f249564eccf71ca8b636494785c97eca3277474b650f90fb04e1158118a699f43d12cd714494d0343bab2aa1fa22df62e5"
            "b70bab111b26d9b34e4ba7ae503b66752632fecf79f943e72cd2a615ed81c8a02923613f02d6a56a0cf1b319176095f31bbdea55"
            "436ca3b2299cb3272034c11015e46f9fce8704653cc4f06164521cd0e7c15fad78687cb8db3e65c2b052410edf6e83da95be7e84"
            "1c2003298a26201c0446ecd59fd87e7ab4501fcd367bdb7465b26c845abe016a7ff97c1fdef5c092705d4d3836a117970b120c6a"
            "6d140c3fd7163698f077576246ca9e843abb7421831bc3234c0eca510c8542a3700172d52caa6893a9117befc9de748189944166"
        ),
    ),
]


@pytest.mark.parametrize("vector", int_vectors)
def test_intconversion(vector) -> None:
    assert rsa.i2osp(vector[0], len(vector[1])) == vector[1]
    assert rsa.i2osp(vector[0], len(vector[1]) + 1) == b"\x00" + vector[1]
    assert rsa.i2osp(vector[0], len(vector[1]) + 2) == b"\x00\x00" + vector[1]
    assert rsa.os2ip(vector[1]) == vector[0]
    assert rsa.os2ip(bytes(42) + vector[1]) == vector[0]

    with pytest.raises(ValueError):
        rsa.i2osp(0, -1)

    with pytest.raises(OverflowError):
        rsa.i2osp(12345, 1)


def test_pss_options() -> None:
    assert rsa.PssOptions().trailer_field == b"\xbc"
    assert rsa.PssOptions(salt_length=20).salt_length == 20
    assert rsa.PssOptions(salt=b"foobar").salt == b"foobar"
    assert rsa.PssOptions(salt_length=6, salt=b"foobar").salt == b"foobar"

    with pytest.raises(ValueError):
        rsa.PssOptions(salt_length=20, salt=b"foobar")


class PubKey(rsa.RsaPublicKey):
    from_key = None
    public_exponent = 65537

    def __init__(self, bits: int) -> None:
        self._modulus = (1 << bits) - 1

    @property
    def modulus(self) -> int:
        return self._modulus


def test_pubkey() -> None:
    for i in range(20):
        pub = PubKey(i * 8)
        assert pub.modlen == i
        assert pub.mod_bits == i * 8
        for j in range(1, 8):
            pub = PubKey(i * 8 + j)
            assert pub.modlen == i + 1
            assert pub.mod_bits == i * 8 + j


class PrivateKey(rsa.RsaPrivateKey):
    def __init__(self, bits: int) -> None:
        self._public = PubKey(bits)

    @property
    def public(self) -> PubKey:
        return self._public

    async def sign(self, msg: bytes) -> rsa.RsaSignature:
        return rsa.RsaSignature(
            self.public,
            rsa.RsaV15Metadata(AsymmetricAlgorithm.RSA, rsa.RsaScheme.PKCS1v1_5, hashes.sha2_256()),
            0,
            b"",
        )


def test_privatekey() -> None:
    priv = PrivateKey(1024)
    assert priv.sig_meta == rsa.RsaPssMetadata(
        AsymmetricAlgorithm.RSA,
        rsa.RsaScheme.PSS,
        hashes.sha2_256(),
        rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.sha2_256()),
        1024 // 8 - 32 - 2,
        b"\xbc",
    )

    priv.default_scheme = rsa.RsaScheme.PKCS1v1_5
    assert priv.sig_meta == rsa.RsaV15Metadata(
        AsymmetricAlgorithm.RSA, rsa.RsaScheme.PKCS1v1_5, hashes.sha2_256(),
    )

    priv.default_scheme = rsa.RsaScheme.RAW
    with pytest.raises(Exception):
        priv.sig_meta

    assert run(priv.sign(b"")).algorithm == AsymmetricAlgorithm.RSA


def test_signature() -> None:
    meta = rsa.RsaSignatureMetadata(algorithm=AsymmetricAlgorithm.RSA, scheme=rsa.RsaScheme.RAW)

    sig = rsa.RsaSignature.from_bytes(key=PubKey(2048), meta=meta, value=b"foo")
    assert sig.int_value == 0x666F6F
    assert sig.bytes_value == bytes(253) + b"foo"

    sig = rsa.RsaSignature.from_bytes(key=PubKey(2048), meta=meta, value=bytes(253) + b"foo")
    assert sig.int_value == 0x666F6F
    assert sig.bytes_value == bytes(253) + b"foo"

    sig = rsa.RsaSignature.from_bytes(key=PubKey(2048), meta=meta, value=bytes(512) + b"foo")
    assert sig.int_value == 0x666F6F
    assert sig.bytes_value == bytes(253) + b"foo"

    with pytest.raises(ValueError, match="Signature is negative"):
        rsa.RsaSignature.from_int(key=PubKey(2048), meta=meta, value=-20)

    sig = rsa.RsaSignature.from_int(key=PubKey(2048), meta=meta, value=0x666F6F)
    assert sig.int_value == 0x666F6F
    assert sig.bytes_value == bytes(253) + b"foo"

    with pytest.raises(ValueError, match="not smaller"):
        key = PubKey(2048)
        key._modulus -= 1000
        rsa.RsaSignature.from_int(key=key, meta=meta, value=((1 << 2048) - 10))


def test_calculate_pss_salt_len() -> None:
    with pytest.raises(ValueError, match="dgst_len"):
        rsa.calculate_pss_salt_len(1024, rsa.PssOptions(), -32)

    with pytest.raises(ValueError, match="em_bits"):
        rsa.calculate_pss_salt_len(0, rsa.PssOptions(), 32)

    with pytest.raises(ValueError, match="Maximum"):
        rsa.calculate_pss_salt_len(128, rsa.PssOptions(), 128)

    assert rsa.calculate_pss_salt_len(1024, rsa.PssOptions(), 32) == 128 - 32 - 2
    assert rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt=bytes(17)), 32) == 17
    assert (
        rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt_length=rsa.PSS_SALT_LEN_MAX), 32) == 128 - 32 - 2
    )
    assert rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt_length=rsa.PSS_SALT_LEN_HASH), 32) == 32
    assert (
        rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt_length=rsa.PSS_SALT_LEN_HASH), 120)
        == 128 - 120 - 2
    )

    with pytest.raises(ValueError, match="salt_length"):
        rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt_length=-15), 32)

    assert rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt_length=15), 32) == 15
    assert rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt_length=66), 32) == 66

    with pytest.raises(ValueError, match="Requested"):
        rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt=bytes(200)), 32)

    with pytest.raises(ValueError, match="Requested"):
        rsa.calculate_pss_salt_len(1024, rsa.PssOptions(salt_length=200), 32)


def test_parse_pss_options() -> None:
    def_hash = hashes.sha2_256()
    pub = PubKey(1024)
    with pytest.raises(TypeError, match="conflicting hash algorithms"):
        rsa.parse_pss_options(
            pub, def_hash, rsa.PssOptions(hash_alg=hashes.sha1()), dgst_hash_alg=hashes.sha2_256()
        )

    assert rsa.parse_pss_options(pub, def_hash).hash_alg == hashes.sha2_256()
    assert rsa.parse_pss_options(pub, default_hash_alg=hashes.md5()).hash_alg == hashes.md5()
    assert rsa.parse_pss_options(pub, def_hash, rsa.PssOptions(hash_alg=hashes.md5())).hash_alg == hashes.md5()
    assert rsa.parse_pss_options(pub, def_hash, dgst_hash_alg=hashes.md5()).hash_alg == hashes.md5()

    mgf_md5 = rsa.MgfAlgorithm(rsa.MgfAlgorithmId.MGF1, rsa.Mgf1Parameters(hashes.md5()))
    mgf_md5_meta = rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.md5())
    mgf_sha2_256_meta = rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.sha2_256())
    assert rsa.parse_pss_options(pub, def_hash).mgf_alg == mgf_sha2_256_meta
    assert rsa.parse_pss_options(pub, default_hash_alg=hashes.md5()).mgf_alg == mgf_md5_meta
    assert rsa.parse_pss_options(pub, def_hash, rsa.PssOptions(mgf_alg=mgf_md5)).mgf_alg == mgf_md5_meta
    assert (
        mgf_sha2_256_meta
        == rsa.parse_pss_options(
            pub, def_hash, rsa.PssOptions(mgf_alg=rsa.MgfAlgorithm(rsa.MgfAlgorithmId.MGF1))
        ).mgf_alg
    )

    params = "params"
    test_alg = rsa.MgfAlgorithm(rsa.MgfAlgorithmId.OTHER, params)
    parsed = rsa.parse_pss_options(pub, def_hash, rsa.PssOptions(mgf_alg=test_alg)).mgf_alg
    assert isinstance(parsed, rsa.OtherMgfMetadata)
    assert parsed.params is params

    with pytest.raises(NotImplementedError):
        rsa.parse_pss_options(pub, def_hash, rsa.PssOptions(mgf_alg=rsa.MgfAlgorithm("foo", "bar")))
