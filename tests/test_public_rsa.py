import pytest
from cryptokey.public import rsa
from cryptokey.public.key import AsymmetricAlgorithm

int_vectors = [
    (0, b''),
    (1, b'\x01'),
    (127, b'\x7f'),
    (128, b'\x80'),
    (129, b'\x81'),
    (255, b'\xff'),
    (256, b'\x01\x00'),
    (257, b'\x01\x01'),
    (258, b'\x01\x02'),
    (511, b'\x01\xff'),
    (512, b'\x02\x00'),
    (31337, b'\x7a\x69'),
    (int(
        '3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067'
        '9821480865132823066470938446095505822317253594081284811174502841027019385211055596446229489549303819'
        '6442881097566593344612847564823378678316527120190914564856692346034861045432664821339360726024914127'
        '3724587006606315588174881520920962829254091715364367892590360011330530548820466521384146951941511609'
        '4330572703657595919530921861173819326117931051185480744623799627495673518857527248912279381830119491'
        '2983367336244065664308602139494639522473719070217986094370277053921717629317675238467481846766940513'
        '2000568127145263560827785771342757789609173637178721468440901224953430146549585371050792279689258923'
        '5420199561121290219608640344181598136297747713099605187072113499999983729780499510597317328160963185'
        '9502445945534690830264252230825334468503526193118817101000313783875288658753320838142061717766914730'
        '3598253490428755468731159562863882353787593751957781857780532171226806613001927876611195909216420198'
    ), bytes.fromhex(
        '01320ef0126ef9258b2f5731dfef4b62d6ce390f70f10e098d8a8e980746de37a02403b7eb2c88a615897fc11ea14a7f1d335a38'
        '1f1bd84dce8f0bab1ff49375891b2ea2649c49d950dd466847475fde63b6d45fef5055ab4a1fbf5884551a12a8a9b83e56509439'
        'eec43e54ed93d5c65d6b5a02f5472ab24f1063656353a118d8e455c22fbd0c7dc2e66a37bda0314ae5da239e7c740c269ee2f129'
        '5be9d6f249564eccf71ca8b636494785c97eca3277474b650f90fb04e1158118a699f43d12cd714494d0343bab2aa1fa22df62e5'
        'b70bab111b26d9b34e4ba7ae503b66752632fecf79f943e72cd2a615ed81c8a02923613f02d6a56a0cf1b319176095f31bbdea55'
        '436ca3b2299cb3272034c11015e46f9fce8704653cc4f06164521cd0e7c15fad78687cb8db3e65c2b052410edf6e83da95be7e84'
        '1c2003298a26201c0446ecd59fd87e7ab4501fcd367bdb7465b26c845abe016a7ff97c1fdef5c092705d4d3836a117970b120c6a'
        '6d140c3fd7163698f077576246ca9e843abb7421831bc3234c0eca510c8542a3700172d52caa6893a9117befc9de748189944166'
    )),
]


@pytest.mark.parametrize("vector", int_vectors)
def test_intconversion(vector) -> None:
    assert rsa.i2osp(vector[0], len(vector[1])) == vector[1]
    assert rsa.i2osp(vector[0], len(vector[1]) + 1) == b'\x00' + vector[1]
    assert rsa.i2osp(vector[0], len(vector[1]) + 2) == b'\x00\x00' + vector[1]
    assert rsa.os2ip(vector[1]) == vector[0]
    assert rsa.os2ip(bytes(42) + vector[1]) == vector[0]

    with pytest.raises(ValueError):
        rsa.i2osp(0, -1)

    with pytest.raises(OverflowError):
        rsa.i2osp(12345, 1)


def test_pss_options() -> None:
    assert rsa.PssOptions().trailer_field == b'\xbc'
    assert rsa.PssOptions(salt_length=20).salt_length == 20
    assert rsa.PssOptions(salt=b'foobar').salt == b'foobar'
    assert rsa.PssOptions(salt_length=6, salt=b'foobar').salt == b'foobar'

    with pytest.raises(ValueError):
        rsa.PssOptions(salt_length=20, salt=b'foobar')


class PubKey(rsa.RsaPublicKey):
    export_public_der = None
    export_public_openssh = None
    export_public_pem = None
    from_key = None
    public_exponent = 65537

    def __init__(self, bits: int) -> None:
        self._modulus = (1 << bits) - 1

    @property
    def modulus(self) -> int:
        return self._modulus


def test_pubkey() -> None:
    for i in range(20):
        assert PubKey(i * 8).modlen == i
        for j in range(1, 8):
            assert PubKey(i * 8 + j).modlen == i + 1


def test_signature() -> None:
    meta = rsa.RsaSignatureMetadata(algorithm=AsymmetricAlgorithm.RSA, scheme=rsa.RsaScheme.RAW)

    with pytest.raises(TypeError, match='value xor int_value'):
        rsa.RsaSignature(key=PubKey(2048), meta=meta, bytes_value=b'foo', int_value=12345)

    sig = rsa.RsaSignature(key=PubKey(2048), meta=meta, bytes_value=b'foo')
    assert sig.int_value == 0x666f6f
    assert sig.bytes_value == bytes(253) + b'foo'

    sig = rsa.RsaSignature(key=PubKey(2048), meta=meta, bytes_value=bytes(253) + b'foo')
    assert sig.int_value == 0x666f6f
    assert sig.bytes_value == bytes(253) + b'foo'

    sig = rsa.RsaSignature(key=PubKey(2048), meta=meta, bytes_value=bytes(512) + b'foo')
    assert sig.int_value == 0x666f6f
    assert sig.bytes_value == bytes(253) + b'foo'

    with pytest.raises(TypeError, match='value xor int_value'):
        rsa.RsaSignature(key=PubKey(2048), meta=meta)

    with pytest.raises(ValueError, match='Signature is negative'):
        rsa.RsaSignature(key=PubKey(2048), meta=meta, int_value=-20)

    sig = rsa.RsaSignature(key=PubKey(2048), meta=meta, int_value=0x666f6f)
    assert sig.int_value == 0x666f6f
    assert sig.bytes_value == bytes(253) + b'foo'

    with pytest.raises(ValueError, match='not smaller'):
        key = PubKey(2048)
        key._modulus -= 1000
        rsa.RsaSignature(key=key, meta=meta, int_value=((1 << 2048) - 10))
