import pytest
from asn1crypto.core import ObjectIdentifier as Asn1ObjId
from cryptokey.oid import OID, ObjectIdentifier, to_int_tuple


def test_int_tuple() -> None:
    t = 1, 20, 300, 4000, 50000
    assert to_int_tuple(["1", "20", 300, 4000, "50000"]) == t
    assert to_int_tuple("1.20.300.4000.50000") == t
    assert to_int_tuple(bytes.fromhex("06083c822c9f20838650")) == t
    assert to_int_tuple(Asn1ObjId("1.20.300.4000.50000")) == t
    assert to_int_tuple(ObjectIdentifier(t)) == t

    with pytest.raises(ValueError):
        to_int_tuple("1.3.6.1.4.1.-10.20")

    with pytest.raises(ValueError):
        to_int_tuple((30, 10))

    with pytest.raises(ValueError):
        to_int_tuple((1, 47, 123))


# fmt: off
def test_object_identifier() -> None:
    oid = ObjectIdentifier("1.20.300.4000.50000")

    tmp = oid.asn1
    assert isinstance(tmp, Asn1ObjId)
    assert tmp.dotted == "1.20.300.4000.50000"

    assert oid.der == bytes.fromhex("06083c822c9f20838650")
    assert bytes(oid) == oid.der

    assert oid.dotted == "1.20.300.4000.50000"
    assert str(oid) == oid.dotted

    assert oid == OID-1-20-300-4000-50000
    assert oid != OID-1-3-6-1-4-1

    assert len(oid) == 5
    assert repr(oid) == "OID-1-20-300-4000-50000"

    assert oid < OID-1-20-300-4000-50000-1
    assert oid < OID-1-20-300-4000-50000-1-2
    assert oid <= OID-1-20-300-4000-50000-1
    assert oid <= OID-1-20-300-4000-50000
    assert oid > OID-1-20-300
    assert oid > OID-1-20-300-4000
    assert oid >= OID-1-20-300-4000
    assert oid >= OID-1-20-300-4000-50000

    assert oid in OID
    assert oid in OID-1
    assert oid in OID-1-20
    assert oid in OID-1-20-300
    assert oid in OID-1-20-300-4000
    assert oid in OID-1-20-300-4000-50000
    assert oid not in OID-1-20-300-4000-50000-600000
    assert oid not in OID-2-20

    assert oid[3] == 4000
    assert oid[0:3] == OID-1-20-300
    assert oid[:3] == OID-1-20-300

    d = {oid: "hello"}
    assert OID-1-3-6 not in d
    assert d[OID-1-20-300-4000-50000] == "hello"
# fmt: on

    with pytest.raises(IndexError):
        oid[42]

    with pytest.raises(IndexError):
        oid[1:2]

    with pytest.raises(IndexError):
        oid[0:2:1]

    with pytest.raises(TypeError):
        oid["Hello World!"]  # type: ignore

    assert (ObjectIdentifier("1") == 1) is False
