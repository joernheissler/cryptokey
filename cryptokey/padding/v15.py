from asn1crypto.algos import DigestInfo
from asn1crypto.core import Null

from ..hashes import MessageDigest


def enc_digestinfo(dgst: MessageDigest) -> bytes:
    return DigestInfo({
        'digest_algorithm': {
            'algorithm': dgst.oid.dotted,
            'parameters': Null(),  # XXX dgst.parameters, add parameters to outer or inner or both?
        },
        'digest': dgst.value,
    }).dump()


def pad_pkcs1_v15(msg: bytes, em_len: int) -> bytes:
    msg_len = len(msg)
    if msg_len > em_len - 11:
        raise ValueError('msg has {} bytes, must be at most {}.'.format(msg_len, em_len - 11))
    return b'\x00\x01' + (b'\xff' * (em_len - msg_len - 3)) + b'\x00' + msg
