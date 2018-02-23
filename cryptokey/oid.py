"""
Implementation of X.660 Object Identifiers.
"""
from __future__ import annotations

from functools import total_ordering
from itertools import chain
from typing import Sequence, Tuple, Union

from asn1crypto.core import ObjectIdentifier as Asn1ObjId


def to_int_tuple(value: OidValue) -> Tuple[int, ...]:
    """
    Convert several types to a tuple of ints.
    """
    if isinstance(value, ObjectIdentifier):
        return value.value
    if isinstance(value, bytes):
        value = Asn1ObjId.load(value)
    if isinstance(value, Asn1ObjId):
        value = value.dotted
    if isinstance(value, str):
        value = value.split('.')

    result = tuple(map(int, value))

    # X.660 6.2.1
    for i in result:
        if i < 0:
            raise ValueError('OID arcs cannot be negative')

    # X.660 6.2.1 a)
    if len(result) > 0 and result[0] > 2:
        raise ValueError('Root arc must be 0, 1 or 2')

    # X.660 6.2.1 b)
    if len(result) > 1 and result[0] < 2 and result[1] > 39:
        raise ValueError('Second arc must be in [0, 39] for roots 0 and 1')

    return result


@total_ordering
class ObjectIdentifier:
    """
    An X.660 Object Identifier.
    """

    def __init__(self, value: OidValue):
        """
        Construct a new ObjectIdentifier
        """
        self.value = to_int_tuple(value)

    @property
    def asn1(self) -> Asn1ObjId:
        """
        Return the asn1crypto version of the ObjectIdentifier.
        """
        return Asn1ObjId(self.dotted)

    @property
    def der(self) -> bytes:
        """
        Return the ASN.1 DER encoding of the ObjectIdentifier.
        """
        return self.asn1.dump()

    @property
    def dotted(self) -> str:
        """
        Return the ObjectIdentifier in dotted form, e.g. "1.3.6.1.4.1".
        """
        return '.'.join(str(v) for v in self.value)

    def __bytes__(self) -> bytes:
        """
        See der.
        """
        return self.der

    def __contains__(self, item: OidValue) -> bool:
        """
        Check for prefixes. E.g. `OID-1-3-6-1-4-1 in OID-1-3-6` is True.
        """
        item = to_int_tuple(item)
        return self.value == item[0:len(self.value)]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (tuple, list, str, bytes, Asn1ObjId, ObjectIdentifier)):
            return NotImplemented
        return self.value == to_int_tuple(other)

    def __getitem__(self, key: Union[int, slice]) -> Union[int, ObjectIdentifier]:
        """
        Return single arc as an int, or a prefix as another ObjectIdentifier.
        """
        if isinstance(key, int):
            return self.value[key]

        if isinstance(key, slice):
            if key.start not in (0, None):
                raise IndexError('Slices need to start at 0')
            if key.step is not None:
                raise IndexError('No step supported')
            return ObjectIdentifier(self.value[key])

        raise TypeError

    def __len__(self) -> int:
        """
        Number of arcs in the OID.
        """
        return len(self.value)

    def __lt__(self, other: OidValue) -> bool:
        """
        Compare two OIDs arc-by-arc. E.g. 1.2.3 < 1.4
        """
        return self.value < to_int_tuple(other)

    def __hash__(self) -> int:
        """
        Compute a hash value of the OID.
        """
        return hash(self.value)

    def __repr__(self) -> str:
        """
        Python expression that results in the same ObjectIdentifier.
        """
        return '-'.join(chain(('OID',), map(str, self.value)))

    def __str__(self) -> str:
        """
        See dotted.
        """
        return self.dotted

    def __sub__(self, other: int) -> ObjectIdentifier:
        """
        Extend the ObjectIdentifier by a new arc.
        Example: foo = OID-1-20-300; foo-4000-50000
        """
        return ObjectIdentifier(self.value + (int(other),))


# Root object ID, to be used like OID-1-3-6-1-4-1
OID = ObjectIdentifier(())

# Type hint for the various OID formats/types supported by the above functions.
OidValue = Union[
    Sequence[Union[int, str]],  # sequence of ints or strings, e.g. [10, 20, "30", "40", 50]
    str,                        # dotted string like "10.20.30.40.50"
    bytes,                      # DER encoded OID, e.g. b"\x06\x05\x83\x24\x1e\x28\x32"
    Asn1ObjId,                  # asn1crypto ObjectIdentifier, e.g. Asn1ObjId("10.20.30.40.50")
    ObjectIdentifier,           # ObjectIdentifier which uses a tuple internally
]
