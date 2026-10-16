from pathlib import Path

import pytest
from PIL import Image

from core.stego_service import StegoService


@pytest.fixture
def carrier(tmp_path: Path) -> Path:
    path = tmp_path / "carrier.png"

    image = Image.new(
        "RGB",
        (300, 300),
        (120, 150, 180),
    )

    image.save(
        path,
        format="PNG",
    )

    return path


def test_full_embed_extract(
    carrier: Path,
    tmp_path: Path,
):
    payload = tmp_path / "message.txt"

    original = (
        b"GhostWire full end-to-end test."
    )

    payload.write_bytes(original)

    output_image = (
        tmp_path / "ghostwire.png"
    )

    output_directory = (
        tmp_path / "recovered"
    )

    service = StegoService()

    service.embed(
        payload_path=payload,
        carrier_path=carrier,
        output_path=output_image,
        password="ghostwire-test",
    )

    assert output_image.exists()

    recovered_path = service.extract(
        carrier_path=output_image,
        output_directory=output_directory,
        password="ghostwire-test",
    )

    assert recovered_path.exists()
    assert recovered_path.name == "message.txt"
    assert recovered_path.read_bytes() == original


def test_wrong_password_fails(
    carrier: Path,
    tmp_path: Path,
):
    payload = tmp_path / "secret.txt"

    payload.write_bytes(
        b"Secret GhostWire data."
    )

    output_image = (
        tmp_path / "ghostwire.png"
    )

    output_directory = (
        tmp_path / "recovered"
    )

    service = StegoService()

    service.embed(
        payload,
        carrier,
        output_image,
        "correct-password",
    )

    with pytest.raises(Exception):
        service.extract(
            output_image,
            output_directory,
            "wrong-password",
        )


def test_missing_carrier(
    tmp_path: Path,
):
    service = StegoService()

    payload = tmp_path / "test.txt"
    payload.write_bytes(b"test")

    with pytest.raises(FileNotFoundError):
        service.embed(
            payload,
            tmp_path / "missing.png",
            tmp_path / "output.png",
            "password",
        )