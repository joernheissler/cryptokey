from typing import Tuple, Dict, Union, Generator, Optional, Mapping

Unarmor = Tuple[str, Dict[str, str], bytes]


def unarmor(pem_bytes: bytes, multiple: bool = False) -> Union[Unarmor, Generator[Unarmor, None, None]]:
    ...


def armor(type_name: str, der_bytes: bytes, headers: Optional[Mapping[str, str]] = None) -> bytes:
    ...
