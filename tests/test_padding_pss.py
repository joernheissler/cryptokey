import pytest
from cryptokey import hashes
from cryptokey.backend import hashlib
from cryptokey.backend.textbook.rsa import TextbookRsaPublicKey
from cryptokey.padding import pss
from cryptokey.public import key, rsa

# Test vector from ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip / pss-int.txt
pub = TextbookRsaPublicKey(
    65537,
    int.from_bytes(
        bytes.fromhex(
            "a2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e"
            "577c2eeaffa20d883a76e65e394c69d4b3c05a1e8fadda27edb2a42bc000fe88"
            "8b9b32c22d15add0cd76b3e7936e19955b220dd17d4ea904b1ec102b2e4de775"
            "1222aa99151024c7cb41cc5ea21d00eeb41f7c800834d2c6e06bce3bce7ea9a5"
        ),
        "big",
    ),
)

msg = bytes.fromhex(
    "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0"
    "dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451"
    "e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc"
)

m2 = bytes.fromhex(
    "000000000000000037b66ae0445843353d47ecb0b4fd14c110e62d6ae3b5d5d002c1bce50c2b65ef88a188d83bce7e61"
)

db_mask = bytes.fromhex(
    "66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefd"
    "d85b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc89739a96643136e8b0f465e87a4535cd4c59b10028d"
)

salt = bytes.fromhex("e3b5d5d002c1bce50c2b65ef88a188d83bce7e61")

emsg = bytes.fromhex(
    "66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af"
    "5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1"
    "e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a"
    "75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc"
)


def test_mgf1() -> None:
    h = hashlib.sha1(m2)
    assert pss.mgf1(h, len(db_mask)) == db_mask
    assert pss.mgf1(h, 0) == b""
    assert pss.mgf1(h, 10) == db_mask[:10]
    assert pss.mgf1(h, 55) == db_mask[:55]
    assert pss.mgf1(h, 64) == db_mask[:64]
    assert len(pss.mgf1(h, 2345)) == 2345

    assert pss.mgf1(h, len(db_mask)) == db_mask
    assert pss.mgf1(h, len(db_mask), hashes.sha1()) == db_mask
    assert pss.mgf1(h, len(db_mask), hashes.sha2_256()) != db_mask


def test_calculate_salt_len() -> None:
    with pytest.raises(ValueError, match="dgst_len"):
        pss.calculate_salt_len(1024, rsa.PssOptions(), -32)

    with pytest.raises(ValueError, match="em_bits"):
        pss.calculate_salt_len(0, rsa.PssOptions(), 32)

    with pytest.raises(ValueError, match="Maximum"):
        pss.calculate_salt_len(128, rsa.PssOptions(), 128)

    assert pss.calculate_salt_len(1024, rsa.PssOptions(), 32) == 128 - 32 - 2
    assert pss.calculate_salt_len(1024, rsa.PssOptions(salt=bytes(17)), 32) == 17
    assert pss.calculate_salt_len(1024, rsa.PssOptions(salt_length=rsa.PSS_SALT_LEN_MAX), 32) == 128 - 32 - 2
    assert pss.calculate_salt_len(1024, rsa.PssOptions(salt_length=rsa.PSS_SALT_LEN_HASH), 32) == 32
    assert pss.calculate_salt_len(1024, rsa.PssOptions(salt_length=rsa.PSS_SALT_LEN_HASH), 120) == 128 - 120 - 2

    with pytest.raises(ValueError, match="salt_length"):
        pss.calculate_salt_len(1024, rsa.PssOptions(salt_length=-15), 32)

    assert pss.calculate_salt_len(1024, rsa.PssOptions(salt_length=15), 32) == 15
    assert pss.calculate_salt_len(1024, rsa.PssOptions(salt_length=66), 32) == 66

    with pytest.raises(ValueError, match="Requested"):
        pss.calculate_salt_len(1024, rsa.PssOptions(salt=bytes(200)), 32)

    with pytest.raises(ValueError, match="Requested"):
        pss.calculate_salt_len(1024, rsa.PssOptions(salt_length=200), 32)


def test_parse_pss_options() -> None:
    def_hash = hashes.sha2_256()
    with pytest.raises(TypeError, match="conflicting hash algorithms"):
        pss.parse_pss_options(
            pub, def_hash, rsa.PssOptions(hash_alg=hashes.sha1()), dgst_hash_alg=hashes.sha2_256()
        )

    assert pss.parse_pss_options(pub, def_hash).hash_alg == hashes.sha2_256()
    assert pss.parse_pss_options(pub, default_hash_alg=hashes.md5()).hash_alg == hashes.md5()
    assert pss.parse_pss_options(pub, def_hash, rsa.PssOptions(hash_alg=hashes.md5())).hash_alg == hashes.md5()
    assert pss.parse_pss_options(pub, def_hash, dgst_hash_alg=hashes.md5()).hash_alg == hashes.md5()

    mgf_md5 = rsa.MgfAlgorithm(rsa.MgfAlgorithmId.MGF1, rsa.Mgf1Parameters(hashes.md5()))
    mgf_md5_meta = rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.md5())
    mgf_sha2_256_meta = rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.sha2_256())
    assert pss.parse_pss_options(pub, def_hash).mgf_alg == mgf_sha2_256_meta
    assert pss.parse_pss_options(pub, default_hash_alg=hashes.md5()).mgf_alg == mgf_md5_meta
    assert pss.parse_pss_options(pub, def_hash, rsa.PssOptions(mgf_alg=mgf_md5)).mgf_alg == mgf_md5_meta
    assert (
        mgf_sha2_256_meta
        == pss.parse_pss_options(
            pub, def_hash, rsa.PssOptions(mgf_alg=rsa.MgfAlgorithm(rsa.MgfAlgorithmId.MGF1))
        ).mgf_alg
    )

    params = "params"
    test_alg = rsa.MgfAlgorithm(rsa.MgfAlgorithmId.OTHER, params)
    parsed = pss.parse_pss_options(pub, def_hash, rsa.PssOptions(mgf_alg=test_alg)).mgf_alg
    assert isinstance(parsed, rsa.OtherMgfMetadata)
    assert parsed.params is params

    with pytest.raises(NotImplementedError):
        pss.parse_pss_options(pub, def_hash, rsa.PssOptions(mgf_alg=rsa.MgfAlgorithm("foo", "bar")))


def test_pad_pss() -> None:
    em, meta = pss.pad_pss(pub, hashes.sha1(), hashlib.sha1(msg), rsa.PssOptions(salt=salt))
    assert em == emsg
    assert meta == rsa.RsaPssMetadata(
        key.AsymmetricAlgorithm.RSA,
        rsa.RsaScheme.PSS,
        hashes.sha1(),
        rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.sha1()),
        len(salt),
        b"\xbc",
    )

    with pytest.raises(NotImplementedError):
        pss.pad_pss(
            pub,
            hashes.sha1(),
            hashlib.sha1(msg),
            rsa.PssOptions(mgf_alg=rsa.MgfAlgorithm(rsa.MgfAlgorithmId.OTHER, "meta")),
        )

    em, meta2 = pss.pad_pss(pub, hashes.sha1(), hashlib.sha1(msg), rsa.PssOptions(salt_length=len(salt)))
    assert em != emsg
    assert meta == meta2


def test_verify_pss() -> None:
    meta = rsa.RsaPssMetadata(
        key.AsymmetricAlgorithm.RSA,
        rsa.RsaScheme.PSS,
        hashes.sha1(),
        rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.sha1()),
        len(salt),
        b"\xbc",
    )
    assert salt == pss.verify_pss(emsg, pub.mod_bits, hashlib.sha1(msg), meta)

    with pytest.raises(ValueError, match=r"Inconsistent hash algorithms"):
        pss.verify_pss(emsg, pub.mod_bits, hashlib.sha2_256(msg), meta)

    with pytest.raises(ValueError, match=r"Expected trailer"):
        pss.verify_pss(emsg[:-1] + b'\xee', pub.mod_bits, hashlib.sha1(msg), meta)

    meta_bad_saltlen = rsa.RsaPssMetadata(
        key.AsymmetricAlgorithm.RSA,
        rsa.RsaScheme.PSS,
        hashes.sha1(),
        rsa.Mgf1Metadata(rsa.MgfAlgorithmId.MGF1, hashes.sha1()),
        15,
        b"\xbc",
    )
    with pytest.raises(ValueError, match=r"Salt length is"):
        pss.verify_pss(emsg, pub.mod_bits, hashlib.sha1(msg), meta_bad_saltlen)

    with pytest.raises(ValueError, match=r"Hash mismatch"):
        pss.verify_pss(emsg, pub.mod_bits, hashlib.sha1(msg + b'foo'), meta)


def test_unpad_pss() -> None:
    assert pss.unpad_pss(emsg, pub.mod_bits, hashes.sha1()) == (salt, hashlib.sha1(m2), b'\xbc')

    with pytest.raises(ValueError, match="Bad parameters"):
        pss.unpad_pss(emsg, 4096, hashes.sha1())

    with pytest.raises(NotImplementedError, match=r"MGF.*not implemented"):
        pss.unpad_pss(emsg, pub.mod_bits, hashes.sha1(), rsa.OtherMgfMetadata(rsa.MgfAlgorithmId.OTHER, "meta"))

    with pytest.raises(ValueError, match="Nonzero leading bytes"):
        pss.unpad_pss(emsg, pub.mod_bits - 32, hashes.sha1())

    with pytest.raises(ValueError, match=r"too short"):
        pss.unpad_pss(emsg, pub.mod_bits, hashes.sha1(), trailer_length=2048)

    with pytest.raises(ValueError, match=r"Nonzero padding bits"):
        pss.unpad_pss(b'\xe6' + emsg[1:], pub.mod_bits, hashes.sha1())

    with pytest.raises(ValueError, match=r"Bad padding"):
        pss.unpad_pss(emsg[:60] + b'\x00' + emsg[61:], pub.mod_bits, hashes.sha1())
