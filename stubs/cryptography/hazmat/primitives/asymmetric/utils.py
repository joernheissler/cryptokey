from ..hashes import HashAlgorithm


class Prehashed(HashAlgorithm):
    def __init__(self, algorithm: HashAlgorithm) -> None: ...
