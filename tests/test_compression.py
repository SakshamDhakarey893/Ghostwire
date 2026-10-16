import pytest

from core.compression import CompressionManager


def test_compression_round_trip():
    original = (
        b"GhostWire compression test. "
        b"GhostWire compression test. "
        b"GhostWire compression test."
    )

    compressed = CompressionManager.compress(original)
    restored = CompressionManager.decompress(compressed)

    assert restored == original


def test_compression_reduces_repeated_data():
    original = b"A" * 10_000

    compressed = CompressionManager.compress(original)

    assert len(compressed) < len(original)


def test_compression_level_validation():
    with pytest.raises(ValueError):
        CompressionManager.compress(
            b"test",
            level=10,
        )


def test_invalid_compressed_data():
    with pytest.raises(ValueError):
        CompressionManager.decompress(
            b"this is not compressed data"
        )


def test_empty_payload_round_trip():
    original = b""

    compressed = CompressionManager.compress(original)
    restored = CompressionManager.decompress(compressed)

    assert restored == original
    