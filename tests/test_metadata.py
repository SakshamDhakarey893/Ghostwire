from core.metadata import MetadataPacket


def test_metadata_round_trip():
    packet = MetadataPacket(
        filename="secret.txt",
        payload_size=1024,
        payload_hash=bytes.fromhex(
            "a" * 64
        ),
    )

    serialized = packet.serialize()
    restored = MetadataPacket.deserialize(serialized)

    assert restored == packet


def test_invalid_hash_size():
    packet = MetadataPacket(
        filename="secret.txt",
        payload_size=100,
        payload_hash=b"invalid",
    )

    try:
        packet.serialize()
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_invalid_magic():
    packet = MetadataPacket(
        filename="secret.txt",
        payload_size=100,
        payload_hash=b"a" * 32,
    )

    serialized = bytearray(packet.serialize())
    serialized[0:2] = b"XX"

    try:
        MetadataPacket.deserialize(bytes(serialized))
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")