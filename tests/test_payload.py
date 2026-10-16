from pathlib import Path

import pytest

from core.payload import PayloadProcessor


def test_payload_round_trip(tmp_path: Path):
    original = (
        b"GhostWire end-to-end payload test.\n"
        b"This data should survive the complete "
        b"processing pipeline."
    )

    payload_file = tmp_path / "secret.txt"
    payload_file.write_bytes(original)

    processor = PayloadProcessor(
        "correct-password"
    )

    prepared = processor.prepare(
        payload_file
    )

    recovered = processor.recover(
        prepared.packet
    )

    assert recovered.filename == "secret.txt"
    assert recovered.data == original


def test_wrong_password_fails(tmp_path: Path):
    payload_file = tmp_path / "secret.txt"
    payload_file.write_bytes(
        b"Top secret GhostWire payload."
    )

    encryptor = PayloadProcessor(
        "correct-password"
    )

    prepared = encryptor.prepare(
        payload_file
    )

    decryptor = PayloadProcessor(
        "wrong-password"
    )

    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        decryptor.recover(
            prepared.packet
        )


def test_modified_packet_fails(tmp_path: Path):
    payload_file = tmp_path / "secret.txt"
    payload_file.write_bytes(
        b"GhostWire integrity test."
    )

    processor = PayloadProcessor(
        "test-password"
    )

    prepared = processor.prepare(
        payload_file
    )

    modified = bytearray(
        prepared.packet
    )

    # Modify encrypted payload.
    modified[-1] ^= 1

    with pytest.raises(Exception):
        processor.recover(
            bytes(modified)
        )


def test_missing_payload_file(tmp_path: Path):
    processor = PayloadProcessor(
        "test-password"
    )

    with pytest.raises(FileNotFoundError):
        processor.prepare(
            tmp_path / "does-not-exist.txt"
        )