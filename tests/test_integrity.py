import pytest

from core.integrity import IntegrityManager


def test_hash_is_deterministic():
    data = b"GhostWire"

    hash1 = IntegrityManager.calculate_hash(data)
    hash2 = IntegrityManager.calculate_hash(data)

    assert hash1 == hash2


def test_hash_is_32_bytes():
    data = b"GhostWire"

    digest = IntegrityManager.calculate_hash(data)

    assert len(digest) == 32


def test_verify_correct_hash():
    data = b"secret payload"

    digest = IntegrityManager.calculate_hash(data)

    assert IntegrityManager.verify_hash(data, digest)


def test_verify_modified_data():
    data = b"secret payload"

    digest = IntegrityManager.calculate_hash(data)

    assert not IntegrityManager.verify_hash(
        b"modified payload",
        digest,
    )


def test_invalid_hash_length():
    with pytest.raises(ValueError):
        IntegrityManager.verify_hash(
            b"secret",
            b"too short",
        )