"""
Examples and glue between `cryptokey` and `asn1crypto` to deal with complex ASN.1 structures.
"""
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, cast

from asn1crypto.core import Null
from asn1crypto.csr import CertificationRequest, CertificationRequestInfo
from asn1crypto.keys import ECPointBitString, NamedCurve
from asn1crypto.x509 import RDNSequence

from .. import hashes
from ..public import ecc, ecdsa, key, rsa

_rsa_v15_algo_map = {
    hashes.HashAlgorithmId.MD5: 'md5_rsa',
    hashes.HashAlgorithmId.SHA1: 'sha1_rsa',
    hashes.HashAlgorithmId.SHA2_224: 'sha224_rsa',
    hashes.HashAlgorithmId.SHA2_256: 'sha256_rsa',
    hashes.HashAlgorithmId.SHA2_384: 'sha384_rsa',
    hashes.HashAlgorithmId.SHA2_512: 'sha512_rsa',
    hashes.HashAlgorithmId.SHA3_224: 'sha3_224_rsa',
    hashes.HashAlgorithmId.SHA3_256: 'sha3_256_rsa',
    hashes.HashAlgorithmId.SHA3_384: 'sha3_384_rsa',
    hashes.HashAlgorithmId.SHA3_512: 'sha3_512_rsa',
}

_ecc_curves_map = {
    ecc.CurveId.NIST_P_256: NamedCurve('secp256r1'),
}

_ecdsa_algo_map = {
    hashes.HashAlgorithmId.SHA2_256: 'sha256_ecdsa',
}


def get_spki(pubkey: key.PublicKey) -> Dict[str, Any]:
    """
    Generate a "SubjectPublicKeyInfo" structure suitable for asn1crypto.
    """

    if pubkey.algorithm == key.AsymmetricAlgorithm.RSA:
        return get_spki_rsa(cast(rsa.RsaPublicKey, pubkey))

    if pubkey.algorithm == key.AsymmetricAlgorithm.ECDSA:
        return get_spki_ec(cast(ecdsa.EccPublicKey, pubkey))

    raise NotImplementedError(f'Algorithm {pubkey.algorithm} not supported')


def get_spki_rsa(pub: rsa.RsaPublicKey) -> Dict[str, Any]:
    """
    Generate "SubjectPublicKeyInfo" structure for RSA.
    """
    # rfc3279/2.3.1
    return {
        'algorithm': {
            'algorithm': 'rsa',
            'parameters': Null(),
        },
        'public_key': {
            'modulus': pub.modulus,
            'public_exponent': pub.public_exponent,
        },
    }


def get_spki_ec(pub: ecdsa.EccPublicKey) -> Dict[str, Any]:
    """
    Generate "SubjectPublicKeyInfo" structure for EC.
    """
    return {
        'algorithm': {
            'algorithm': 'ec',
            'parameters': _ecc_curves_map[pub.curve_id],
        },
        'public_key': ECPointBitString.from_coords(pub.point.x, pub.point.y),
    }


def get_sig_alg(sig: key.Signature) -> Dict[str, Any]:
    """
    Create `SignedDigestAlgorithm` structure.
    """
    if sig.meta.algorithm == key.AsymmetricAlgorithm.RSA:
        return get_sig_alg_rsa(cast(rsa.RsaSignature, sig))

    if sig.meta.algorithm == key.AsymmetricAlgorithm.ECDSA:
        return get_sig_alg_ecdsa(cast(ecdsa.EcdsaSignature, sig))

    raise NotImplementedError(f'Algorithm {sig.meta.algorithm} not supported')


def get_sig_bytes(sig: key.Signature) -> bytes:
    """
    Get bytes of signature
    """
    if sig.meta.algorithm == key.AsymmetricAlgorithm.RSA:
        return cast(rsa.RsaSignature, sig).bytes_value

    if sig.meta.algorithm == key.AsymmetricAlgorithm.ECDSA:
        return cast(ecdsa.EcdsaSignature, sig).der

    raise NotImplementedError(f'Algorithm {sig.meta.algorithm} not supported')


def get_sig_alg_rsa(sig: rsa.RsaSignature) -> Dict[str, Any]:
    """
    Create `SignedDigestAlgorithm` structure for RSA.
    """
    if sig.meta.scheme == rsa.RsaScheme.PKCS1v1_5:
        return get_sig_alg_rsa_v15(cast(rsa.RsaV15Metadata, sig.meta))

    if sig.meta.scheme == rsa.RsaScheme.PSS:
        return get_sig_alg_rsa_pss(cast(rsa.RsaPssMetadata, sig.meta))

    raise NotImplementedError(f'Scheme {sig.meta.scheme} not supported')


def get_sig_alg_rsa_v15(meta: rsa.RsaV15Metadata) -> Dict[str, Any]:
    """
    Create `SignedDigestAlgorithm` structure for RSA with PKCS#1 v.15
    """
    try:
        algo = _rsa_v15_algo_map[meta.hash_alg.algorithm_id]
    except KeyError:
        raise NotImplementedError(f'Hash algorithm {meta.hash_alg.algorithm_id} not supported')

    return {
        'algorithm': algo,
        'parameters': {},
    }


def get_sig_alg_rsa_pss(meta: rsa.RsaPssMetadata) -> Dict[str, Any]:
    """
    Create `SignedDigestAlgorithm` structure for RSA with PSS.
    """

    if meta.mgf_alg.algorithm_id != rsa.MgfAlgorithmId.MGF1:
        raise NotImplementedError(f'MGF algorithm {meta.mgf_alg.algorithm_id} not supported')
    mgf1_params = cast(rsa.Mgf1Metadata, meta.mgf_alg)

    # XXX change types to disallow None
    assert mgf1_params.hash_alg

    return {
        'algorithm': 'rsassa_pss',
        'parameters': {
            'hash_algorithm': {
                'algorithm': str(hashes.get_algo_oid(meta.hash_alg)),
                'parameters': {},
            },
            'mask_gen_algorithm': {
                'algorithm': 'mgf1',
                'parameters': {
                    'algorithm': str(hashes.get_algo_oid(mgf1_params.hash_alg)),
                    'parameters': {},
                },
            },
            'salt_length': meta.salt_length,
            'trailer_field': 'trailer_field_bc',
        },
    }


def get_sig_alg_ecdsa(sig: ecdsa.EcdsaSignature) -> Dict[str, Any]:
    """
    Create `SignedDigestAlgorithm` structure for ECDSA.
    """
    try:
        algo = _ecdsa_algo_map[sig.meta.hash_alg.algorithm_id]
    except KeyError:
        raise NotImplementedError(f'Hash algorithm {sig.meta.hash_alg.algorithm_id} not supported')

    return {
        'algorithm': algo,
    }


async def build_csr(priv: key.PrivateKey, subject: Sequence[Tuple[str, Any]],
                    attributes: Optional[List[Mapping[str, Any]]] = None) -> bytes:
    """
    Create a PKCS#10 Certificate Signing Request.
    """
    cri = CertificationRequestInfo({
        'version': 'v1',
        'subject': RDNSequence([
            [{
                'type': typ,
                'value': value,
            }]
            for typ, value in subject
        ]),
        'subject_pk_info': get_spki(priv.public),
        'attributes': attributes or [],
    })

    sig = await priv.sign(cri.dump())

    return CertificationRequest({
        'certification_request_info': cri,
        'signature_algorithm': get_sig_alg(sig),
        'signature': get_sig_bytes(sig),
    }).dump()
