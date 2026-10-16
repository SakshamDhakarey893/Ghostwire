from pathlib import Path

import pytest
from PIL import Image

from core.image_stego import ImageStego
from core.randomizer import Randomizer
from core.stego_service import StegoService


def create_test_carrier(path: Path) -> None:
    """Create a PNG carrier suitable for testing."""

    width = 256
    height = 256

    image = Image.new(
        "RGB",
        (width, height),
    )

    pixels = image.load()

    for y in range(height):
        for x in range(width):
            pixels[x, y] = (
                (x * 3) % 256,
                (y * 3) % 256,
                ((x + y) * 3) % 256,
            )

    image.save(
        path,
        format="PNG",
    )


def test_wrong_password_fails_extraction(
    tmp_path: Path,
) -> None:
    """
    A payload embedded with one password must not be
    recoverable using a different password.
    """

    service = StegoService()

    payload_path = tmp_path / "secret.txt"
    carrier_path = tmp_path / "carrier.png"
    stego_path = tmp_path / "stego.png"
    output_directory = tmp_path / "recovered"

    payload_path.write_bytes(
        b"GhostWire security test payload."
    )

    create_test_carrier(carrier_path)

    # ---------------------------------------------------------
    # Embed using the correct password.
    # ---------------------------------------------------------

    service.embed(
        payload_path=payload_path,
        carrier_path=carrier_path,
        output_path=stego_path,
        password="correct-password",
    )

    assert stego_path.exists()

    # ---------------------------------------------------------
    # Extraction with the wrong password MUST fail.
    # ---------------------------------------------------------

    with pytest.raises(Exception):
        service.extract(
            carrier_path=stego_path,
            output_directory=output_directory,
            password="wrong-password",
        )

def test_tampered_stego_image_fails_extraction(
    tmp_path: Path,
) -> None:
    """
    Modifying the stego image after embedding should cause
    extraction to fail or the recovered payload to fail
    integrity validation.
    """

    service = StegoService()

    payload = tmp_path / "secret.txt"
    carrier = tmp_path / "carrier.png"
    stego_image = tmp_path / "stego.png"
    output_dir = tmp_path / "output"

    payload.write_bytes(b"GhostWire security test payload.")

    # Create a carrier image.
    create_test_carrier(carrier)

    service.embed(
        payload,
        carrier,
        stego_image,
        "password",
    )

    # Tamper with the stego image at a position actually used by the payload.
    image = Image.open(stego_image).convert("RGB")
    pixels = image.load()

    capacity = ImageStego.calculate_capacity(stego_image)
    fp = ImageStego.calculate_fingerprint(stego_image)
    positions = Randomizer("password", carrier_fingerprint=fp).generate_positions(
        total_pixels=capacity,
        required_bits=192,
    )
    tamper_pos = positions[0]
    x, y, channel = ImageStego.index_to_coord(tamper_pos, image.width)

    pixel = list(pixels[x, y])
    pixel[channel] ^= 1
    pixels[x, y] = tuple(pixel)

    image.save(stego_image)

    output_dir.mkdir()

    with pytest.raises(Exception):
        service.extract(
            stego_image,
            output_dir,
            "password",
        )