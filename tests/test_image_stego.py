from pathlib import Path

import pytest
from PIL import Image

from core.image_stego import ImageStego
from core.randomizer import Randomizer


@pytest.fixture
def carrier_image(tmp_path: Path) -> Path:
    """Create a temporary PNG carrier."""

    path = tmp_path / "carrier.png"

    image = Image.new(
        "RGB",
        (100, 100),
        (120, 150, 180),
    )

    image.save(path, format="PNG")

    return path


def test_capacity(carrier_image: Path):
    capacity = ImageStego.calculate_capacity(
        carrier_image
    )

    assert capacity == 100 * 100 * 3


def test_embed_and_extract(carrier_image: Path, tmp_path: Path):
    payload = b"GhostWire"

    output = tmp_path / "stego.png"

    stego = ImageStego(carrier_image)

    positions = Randomizer(
        "test-password"
    ).generate_positions(
        stego.calculate_capacity(carrier_image),
        len(payload) * 8,
    )

    stego.embed(
        payload,
        positions,
        output,
    )

    extractor = ImageStego(output)

    extracted = extractor.extract(
        len(payload) * 8,
        positions,
    )

    assert extracted == payload


def test_wrong_positions_do_not_recover_payload(
    carrier_image: Path,
    tmp_path: Path,
):
    payload = b"GhostWire"

    output = tmp_path / "stego.png"

    stego = ImageStego(carrier_image)

    capacity = stego.calculate_capacity(
        carrier_image
    )

    correct_positions = Randomizer(
        "correct-password"
    ).generate_positions(
        capacity,
        len(payload) * 8,
    )

    wrong_positions = Randomizer(
        "wrong-password"
    ).generate_positions(
        capacity,
        len(payload) * 8,
    )

    stego.embed(
        payload,
        correct_positions,
        output,
    )

    extractor = ImageStego(output)

    extracted = extractor.extract(
        len(payload) * 8,
        wrong_positions,
    )

    assert extracted != payload


def test_payload_too_large(carrier_image: Path, tmp_path: Path):
    payload = b"A" * 10_000

    output = tmp_path / "stego.png"

    stego = ImageStego(carrier_image)

    positions = Randomizer(
        "test-password"
    ).generate_positions(
        stego.calculate_capacity(carrier_image),
        stego.calculate_capacity(carrier_image),
    )

    with pytest.raises(ValueError):
        stego.embed(
            payload,
            positions,
            output,
        )