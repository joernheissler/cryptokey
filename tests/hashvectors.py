from dataclasses import asdict, dataclass
from types import ModuleType
from typing import List, Optional, Tuple, Type

import pytest
from cryptokey import hashes
from cryptokey.oid import OID, ObjectIdentifier


@dataclass
class HashVector:
    algo: hashes.HashAlgorithm
    oid: Optional[ObjectIdentifier]
    digests: Tuple[str, str, str]


hash_inputs = [
    b'',
    b'foobar',
    b'The quick brown fox jumps over the lazy dog',
]


hash_vectors: List[HashVector] = [
    HashVector(hashes.blake2b(4), OID-1-3-6-1-4-1-1722-12-2-1-1, (
        '1271cf25',
        '6a2639d8',
        'f1d38416',
    )),
    HashVector(hashes.blake2b(13), None, (
        '50b4dc6f148a3f25b974e5c829',
        'f61701e5f1d06e069d2bca09a3',
        '4dbd534ed61d012504090d937f',
    )),
    HashVector(hashes.blake2b(16), OID-1-3-6-1-4-1-1722-12-2-1-4, (
        'cae66941d9efbd404e4d88758ea67670',
        '13b16eec2597e4d5616a70b1abd318b0',
        '249df9a49f517ddcd37f5c897620ec73',
    )),
    HashVector(hashes.blake2b(32), OID-1-3-6-1-4-1-1722-12-2-1-8, (
        '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8',
        '93a0e84a8cdd4166267dbe1263e937f08087723ac24e7dcc35b3d5941775ef47',
        '01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9',
    )),
    HashVector(hashes.blake2b(36), OID-1-3-6-1-4-1-1722-12-2-1-9, (
        '92f3592c601fe36aa32c62e305f965905a2982dee6a45c09011ddf05f9cf9b7b5609414f',
        'a7ee8550074a9282d099afc98850cb7c081f0593db1727caa0256dc1c542c97b7c9e5909',
        '58bc84bc673a61787169cc0e235b583997f2c150731e1180ae2dae00fa505671fb4196ba',
    )),
    HashVector(hashes.blake2b(64), OID-1-3-6-1-4-1-1722-12-2-1-16, (
        '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419'
        'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
        '8df31f60d6aeabd01b7dc83f277d0e24cbe104f7290ff89077a7eb58646068ed'
        'fe1a83022866c46f65fb91612e516e0ecfa5cb25fc16b37d2c8d73732fe74cb2',
        'a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673'
        'f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918',
    )),
    HashVector(hashes.blake2s(4), OID-1-3-6-1-4-1-1722-12-2-2-1, (
        '36e9d246',
        '041e9c4f',
        '3ae238c4',
    )),
    HashVector(hashes.blake2s(8), OID-1-3-6-1-4-1-1722-12-2-2-2, (
        'ef2a8b78dd80da9c',
        '7992f6493b57cd55',
        'ea9f41ceddb73568',
    )),
    HashVector(hashes.blake2s(13), None, (
        '758fe2c70fa22afd145e08c8c1',
        'c707e5aa51f7cfe5d2da05655a',
        'f8c6682ff695766ff06082e7f8',
    )),
    HashVector(hashes.blake2s(16), OID-1-3-6-1-4-1-1722-12-2-2-4, (
        '64550d6ffe2c0a01a14aba1eade0200c',
        '317ffec56d1e2b93098d8d44d3124938',
        '96fd07258925748a0d2fb1c8a1167a73',
    )),
    HashVector(hashes.blake2s(32), OID-1-3-6-1-4-1-1722-12-2-2-8, (
        '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9',
        '03a4921c6b0aa0e5bed57228a3b6fd61bec160d46fa610ce6742dd51ab311f43',
        '606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812',
    )),
    HashVector(hashes.md5(), OID-1-2-840-113549-2-5, (
        'd41d8cd98f00b204e9800998ecf8427e',
        '3858f62230ac3c915f300c664312c63f',
        '9e107d9d372bb6826bd81d3542a419d6',
    )),
    HashVector(hashes.ripemd_160(), OID-1-3-36-3-2-1, (
        '9c1185a5c5e9fc54612808977ee8f548b2258d31',
        'a06e327ea7388c18e4740e350ed4e60f2e04fc41',
        '37f332f68db77bd9d7edd4969571ad671cf9dd3b',
    )),
    HashVector(hashes.sha1(), OID-1-3-14-3-2-26, (
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        '8843d7f92416211de9ebb963ff4ce28125932878',
        '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
    )),
    HashVector(hashes.sha2_224(), OID-2-16-840-1-101-3-4-2-4, (
        'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
        'de76c3e567fca9d246f5f8d3b2e704a38c3c5e258988ab525f941db8',
        '730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525',
    )),
    HashVector(hashes.sha2_256(), OID-2-16-840-1-101-3-4-2-1, (
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2',
        'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
    )),
    HashVector(hashes.sha2_384(), OID-2-16-840-1-101-3-4-2-2, (
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        '3c9c30d9f665e74d515c842960d4a451c83a0125fd3de7392d7b37231af10c72ea58aedfcdf89a5765bf902af93ecf06',
        'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1',
    )),
    HashVector(hashes.sha2_512(), OID-2-16-840-1-101-3-4-2-3, (
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
        '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        '0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f8161'
        '6a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425',
        '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64'
        '2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6',
    )),
    HashVector(hashes.sha2_512_224(), OID-2-16-840-1-101-3-4-2-5, (
        '6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4',
        '39e7c95bf3f92dcd171d452d060a3dc3b7ca979e0457f10ca5b0e4b3',
        '944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37',
    )),
    HashVector(hashes.sha2_512_256(), OID-2-16-840-1-101-3-4-2-6, (
        'c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a',
        'd014c752bc2be868e16330f47e0c316a5967bcbc9c286a457761d7055b9214ce',
        'dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d',
    )),
    HashVector(hashes.sha3_224(), OID-2-16-840-1-101-3-4-2-7, (
        '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
        '1ad852ba147a715fe5a3df39a741fad08186c303c7d21cefb7be763b',
        'd15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795',
    )),
    HashVector(hashes.sha3_256(), OID-2-16-840-1-101-3-4-2-8, (
        'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
        '09234807e4af85f17c66b48ee3bca89dffd1f1233659f9f940a2b17b0b8c6bc5',
        '69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04',
    )),
    HashVector(hashes.sha3_384(), OID-2-16-840-1-101-3-4-2-9, (
        '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
        '0fa8abfbdaf924ad307b74dd2ed183b9a4a398891a2f6bac8fd2db7041b77f068580f9c6c66f699b496c2da1cbcc7ed8',
        '7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41',
    )),
    HashVector(hashes.sha3_512(), OID-2-16-840-1-101-3-4-2-10, (
        'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6'
        '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
        'ff32a30c3af5012ea395827a3e99a13073c3a8d8410a708568ff7e6eb85968fc'
        'cfebaea039bc21411e9d43fdb9a851b529b9960ffea8679199781b8f45ca85e2',
        '01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff'
        '23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450',
    )),
    HashVector(hashes.shake_128(), OID-2-16-840-1-101-3-4-2-11, (
        '7f9c2ba4e88f827d616045507605853e',
        'a2a5933ad57401cfc082ec7db10c730f',
        'f4202e3c5852f9182a0430fd8144f0a7',
    )),
    HashVector(hashes.shake_128_len(13), OID-2-16-840-1-101-3-4-2-17, (
        '7f9c2ba4e88f827d6160455076',
        'a2a5933ad57401cfc082ec7db1',
        'f4202e3c5852f9182a0430fd81',
    )),
    HashVector(hashes.shake_256(), OID-2-16-840-1-101-3-4-2-12, (
        '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
        'd9b219853298b92373f90479065636a9d143e024f071ac3f7c84636da948ad69',
        '2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca',
    )),
    HashVector(hashes.shake_256_len(13), OID-2-16-840-1-101-3-4-2-18, (
        '46b9dd2b0ba88d13233b3feb74',
        'd9b219853298b92373f9047906',
        '2f671343d9b2e1604dc9dcf075',
    )),
    HashVector(hashes.HashAlgorithm(0), OID-1-3-5-7-9, (  # Algorithm isn't defined at all.
        '01230123abcdef',
        '01230123abcdef',
        '01230123abcdef',
    )),

    # No backend implements this:
    HashVector(hashes.HashAlgorithm(hashes.HashAlgorithmId._TEST_DUMMY), None, (
        'abcdef',
        'abcdef',
        'abcdef',
    )),
]


def check_vector(vector: HashVector, backend: ModuleType, impl: Type[hashes.HashFunction]) -> None:
    if vector.algo.algorithm_id != 0:
        assert hashes.get_algo_size(vector.algo) == len(vector.digests[0]) // 2
        if vector.oid is None:
            with pytest.raises(ValueError):
                hashes.get_algo_oid(vector.algo)
        else:
            assert hashes.get_algo_oid(vector.algo) == vector.oid

    for inp, out in zip(hash_inputs, vector.digests):
        out_bytes = bytes.fromhex(out)

        # Create a MessageDigest with HashFunction.hash and verify it against the test data.
        dig0 = impl.hash(vector.algo, inp)
        assert dig0.value == out_bytes
        assert dig0.algorithm == vector.algo
        if vector.oid:
            assert dig0.oid == vector.oid
        else:
            with pytest.raises(ValueError):
                assert dig0.oid == vector.oid
        assert dig0.hashfunc is impl
        assert dig0.size == len(out_bytes)
        assert dig0.hexvalue == out
        assert bytes(dig0) == out_bytes
        assert len(dig0) == len(out_bytes)
        assert dig0.new().update(inp).finalize() == dig0
        assert dig0.new().update(inp + b'!').finalize() != dig0

        h = impl(vector.algo)

        # Checks on Hash Function before updating it with data
        assert h.algorithm == vector.algo
        if vector.oid:
            assert h.oid == vector.oid
        else:
            with pytest.raises(ValueError):
                assert h.oid == vector.oid
        assert h.size == len(out_bytes)

        # Load data and compute digest.
        length = len(inp) // 4
        h.update(inp[0*length:1*length])
        h.update(inp[1*length:2*length])
        h.update(inp[2*length:3*length])
        h.update(inp[3*length:])
        dig1 = h.finalize()
        assert h.finalize() is dig1
        assert dig1 == dig0

        # Same checks on Hash Function after updating it with data. It should not have changed.
        assert h.algorithm == vector.algo
        if vector.oid:
            assert h.oid == vector.oid
        else:
            with pytest.raises(ValueError):
                assert h.oid == vector.oid
        assert h.size == len(out_bytes)

        # test copy function
        prefix = impl(vector.algo)
        prefix.update(inp[0*length:1*length])
        copy0 = prefix.copy()
        copy1 = prefix.copy()
        prefix.update(inp[1*length:])
        copy0.update(inp[1*length:2*length])
        copy0.update(inp[2*length:])
        copy1.update(b'!')
        assert copy0.finalize() == prefix.finalize() == dig0
        assert copy0.finalize() != copy1.finalize()

        # test shortcuts
        func = getattr(backend, vector.algo.algorithm_id.name.lower())
        param = vector.algo.parameters
        dig2 = func(inp, **(asdict(param) if param else {}))
        assert dig2 == dig0
