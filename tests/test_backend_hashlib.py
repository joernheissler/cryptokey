import pytest
from cryptokey.backend import hashlib
from hashvectors import check_vector, hash_vectors


@pytest.mark.parametrize("vector", hash_vectors)
def test_hashlib(vector) -> None:
    try:
        check_vector(vector, hashlib, hashlib.HashlibHash)
    except NotImplementedError:
        pass
