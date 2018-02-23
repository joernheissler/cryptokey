import pytest
from cryptokey.backend.cryptography import hashes as backend
from hashvectors import check_vector, hash_vectors


@pytest.mark.parametrize("vector", hash_vectors)
def test_vectors(vector) -> None:
    try:
        check_vector(vector, backend, backend.CryptographyHash)
    except NotImplementedError:
        pass
