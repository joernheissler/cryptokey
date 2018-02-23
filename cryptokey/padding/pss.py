"""
Implementation of Probabilistic Signature Scheme (PSS) padding
according to rfc8017
"""
from __future__ import annotations

from os import urandom
from typing import Optional, Tuple, cast

from .. import hashes
from ..backend.hashlib import HashlibHash
from ..public import key, rsa


def mgf1(seed: hashes.MessageDigest, mask_len: int, hash_alg: Optional[hashes.HashAlgorithm] = None) -> bytes:
    prefix: hashes.HashFunction = HashlibHash(hash_alg) if hash_alg else seed.new()
    prefix.update(seed.value)

    buf = bytearray()
    count = 0
    while len(buf) < mask_len:
        buf.extend(prefix.copy().update(rsa.i2osp(count, 4)).finalize().value)
        count += 1
    del buf[mask_len:]
    return buf


# # XXX functions to decode (e.g. extract salt) and verify PSS. It should also be possible
# # to determine the salt without knowing the size before.


def calculate_salt_len(mod_bits: int, opt: rsa.PssOptions, dgst_len: int) -> int:
    """
    Calculate and validate the length of the salt.

    mod_bits: length of the modulus in bits
    opt: Pss Options; may contain None values
    dgst_len: length of digest in bytes
    """

    # 8.1.1/1) One less modulus size to ensure that the encoded message is always smaller than the modulus.
    em_bits = mod_bits - 1

    if dgst_len < 0:
        raise ValueError('dgst_len cannot be negative')

    if em_bits < 0:
        raise ValueError('em_bits cannot be negative')

    # 9.1.1/Output)
    em_len = (em_bits + 7) // 8

    # Usually 1 (for b'\xbc')
    trailer_len = len(opt.trailer_field)

    # 9.1.1/3) specifies the upper bound of salt_len. Rationale:
    #
    # 9.1.1/8) db_len = ps_len + 1 + salt_len
    # 9.1.1/10) mask_len = db_len
    # 9.1.1/12) em_len = mask_len + dgst_len + trailer_len
    # => salt_len = em_len - 1 - dgst_len - trailer_len - ps_len
    # 9.1.1/7) allows ps_len = 0.
    # => max_salt_len = em_len - 1 - dgst_len - trailer_len
    max_salt_len = em_len - 1 - dgst_len - trailer_len

    if max_salt_len < 0:
        raise ValueError('Maximum salt length cannot be negative')

    if opt.salt_length is None:
        salt_len = max_salt_len if opt.salt is None else len(opt.salt)
    elif opt.salt_length == rsa.PSS_SALT_LEN_MAX:
        salt_len = max_salt_len
    elif opt.salt_length == rsa.PSS_SALT_LEN_HASH:
        # Try to use digest len (9.1/4), but if it's bigger than max_salt_len, use that.
        salt_len = min(dgst_len, max_salt_len)
    else:
        if opt.salt_length < 0:
            raise ValueError('salt_length cannot be negative')

        salt_len = opt.salt_length

    if salt_len > max_salt_len:
        raise ValueError('Requested salt length too big')

    return salt_len


def parse_pss_options(
        pub: rsa.RsaPublicKey,
        default_hash_alg: hashes.HashAlgorithm,
        options: Optional[rsa.PssOptions] = None,
        dgst_hash_alg: Optional[hashes.HashAlgorithm] = None,
) -> rsa.RsaPssMetadata:
    """
    """

    opt = options or rsa.PssOptions()

    if dgst_hash_alg and opt.hash_alg and dgst_hash_alg != opt.hash_alg:
        raise TypeError('conflicting hash algorithms')
    hash_alg = dgst_hash_alg or opt.hash_alg or default_hash_alg

    opt_mgf = opt.mgf_alg or rsa.MgfAlgorithm(rsa.MgfAlgorithmId.MGF1)

    mgf_alg: rsa.MgfMetadata  # mypy doesn't see that below Mgf1Metadata and OtherMgfMetadata have same parent type.

    if opt_mgf.algorithm_id == rsa.MgfAlgorithmId.MGF1:
        mgf_params = cast(rsa.Mgf1Parameters, opt_mgf.parameters) if opt_mgf.parameters else rsa.Mgf1Parameters()
        mgf_alg = rsa.Mgf1Metadata(
            rsa.MgfAlgorithmId.MGF1,
            mgf_params.hash_alg or hash_alg,
        )
    elif opt_mgf.algorithm_id == rsa.MgfAlgorithmId.OTHER:
        mgf_alg = rsa.OtherMgfMetadata(rsa.MgfAlgorithmId.OTHER, opt_mgf.parameters)
    else:
        raise NotImplementedError(f'MGF algorithm {opt_mgf.algorithm_id} not implemented')

    salt_length = calculate_salt_len(pub.modulus.bit_length(), opt, hashes.get_algo_size(hash_alg))

    return rsa.RsaPssMetadata(
        algorithm=key.AsymmetricAlgorithm.RSA,
        scheme=rsa.RsaScheme.PSS,
        hash_alg=hash_alg,
        mgf_alg=mgf_alg,
        salt_length=salt_length,
        trailer_field=opt.trailer_field,
    )


def pad_pss(
        pub: rsa.RsaPublicKey,
        default_hash_alg: hashes.HashAlgorithm,
        dgst: hashes.MessageDigest,
        options: Optional[rsa.PssOptions] = None,
) -> Tuple[bytes, rsa.RsaPssMetadata]:
    """
    """

    # 8.1.1/1) One less modulus size to ensure that the encoded message is always smaller than the modulus.
    mod_bits = pub.modulus.bit_length()
    em_bits = mod_bits - 1

    # 9.1.1/Output)
    em_len = (em_bits + 7) // 8

    # 9.1.1/1 and /2 are skipped because the hash is already computed.

    # Includes 9.1.1/3
    meta = parse_pss_options(pub, default_hash_alg, options, dgst.algorithm)
    if meta.mgf_alg.algorithm_id != rsa.MgfAlgorithmId.MGF1:
        raise NotImplementedError(f'MGF {meta.mgf_alg.algorithm_id} not implemented')
    mgf_alg = cast(rsa.Mgf1Metadata, meta.mgf_alg)

    # 9.1.1/4)
    if options and options.salt is not None:
        # Use supplied salt
        salt = options.salt
    else:
        # Generate random salt. "urandom" is good enough (8.1 last paragraph).
        salt = urandom(meta.salt_length)

    # 9.1.1/5)
    tmp = dgst.new()
    tmp.update(bytes(8))
    tmp.update(dgst.value)
    tmp.update(salt)

    # 9.1.1/6)
    h = tmp.finalize()

    # 9.1.1/7) PS consists of zero octets, so it doesn't appear anywhere.
    # 9.1.1/8) Use integers as python has no xor operator on bytes.
    data_block = (1 << (len(salt) * 8)) | rsa.os2ip(salt)

    hash_trailer_len = h.size + len(meta.trailer_field)

    # 9.1.1/9)
    db_mask = mgf1(h, em_len - hash_trailer_len, mgf_alg.hash_alg)

    # 9.1.1/10)
    masked_db = data_block ^ rsa.os2ip(db_mask)

    # 9.1.1/11) This uses an all-1-mask for the whole masked_db, not just the leftmost octet.
    masked_db &= (1 << (em_bits - 8 * hash_trailer_len)) - 1

    # 9.1.1/12)
    enc_msg = rsa.i2osp(masked_db, em_len - hash_trailer_len) + h.value + meta.trailer_field

    # 9.1.1/13)
    return enc_msg, meta
