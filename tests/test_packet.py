import pytest

from core.packet import (
    HEADER_SIZE,
    MAGIC,
    MAX_PACKET_SIZE,
    PacketHeader,
)


def test_header_round_trip():
    header = PacketHeader(
        packet_size=4096,
        flags=0,
    )

    serialized = header.serialize()

    assert len(serialized) == HEADER_SIZE

    restored = PacketHeader.deserialize(
        serialized
    )

    assert restored == header


def test_magic_is_present():
    header = PacketHeader(
        packet_size=100,
    )

    serialized = header.serialize()

    assert serialized[:2] == MAGIC


def test_negative_packet_size():
    header = PacketHeader(
        packet_size=-1,
    )

    with pytest.raises(ValueError):
        header.serialize()


def test_packet_size_limit():
    header = PacketHeader(
        packet_size=MAX_PACKET_SIZE + 1,
    )

    with pytest.raises(ValueError):
        header.serialize()


def test_invalid_magic():
    header = PacketHeader(
        packet_size=100,
    )

    serialized = bytearray(
        header.serialize()
    )

    serialized[:2] = b"XX"

    with pytest.raises(ValueError):
        PacketHeader.deserialize(
            bytes(serialized)
        )


def test_invalid_version():
    header = PacketHeader(
        packet_size=100,
    )

    serialized = bytearray(
        header.serialize()
    )

    serialized[2] = 99

    with pytest.raises(ValueError):
        PacketHeader.deserialize(
            bytes(serialized)
        )


def test_incomplete_header():
    with pytest.raises(ValueError):
        PacketHeader.deserialize(
            b"GW"
        )