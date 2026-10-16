from pathlib import Path

from PIL import Image

from core.stego_service import StegoService


def create_test_carrier(path: Path) -> None:
    """Create a deterministic PNG carrier for testing."""

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


def test_full_embed_extract_cycle(tmp_path: Path) -> None:
    """Verify the complete GhostWire embed/extract pipeline."""

    service = StegoService()

    # ---------------------------------------------------------
    # Paths
    # ---------------------------------------------------------

    payload_path = tmp_path / "secret.txt"
    carrier_path = tmp_path / "carrier.png"
    stego_path = tmp_path / "stego.png"
    output_directory = tmp_path / "recovered"

    # ---------------------------------------------------------
    # Create original payload
    # ---------------------------------------------------------

    original_data = (
        b"GhostWire end-to-end integration test.\n"
        b"This payload should survive the complete "
        b"embed and extraction pipeline.\n"
    )

    payload_path.write_bytes(original_data)

    # ---------------------------------------------------------
    # Create carrier image
    # ---------------------------------------------------------

    create_test_carrier(carrier_path)

    assert carrier_path.exists()

    # ---------------------------------------------------------
    # Embed
    # ---------------------------------------------------------

    result = service.embed(
        payload_path=payload_path,
        carrier_path=carrier_path,
        output_path=stego_path,
        password="test-password",
    )

    # ---------------------------------------------------------
    # Verify stego image
    # ---------------------------------------------------------

    assert result == stego_path
    assert stego_path.exists()
    assert stego_path.stat().st_size > 0

    # ---------------------------------------------------------
    # Extract
    # ---------------------------------------------------------

    recovered_path = service.extract(
        carrier_path=stego_path,
        output_directory=output_directory,
        password="test-password",
    )

    # ---------------------------------------------------------
    # Verify recovered file
    # ---------------------------------------------------------

    assert recovered_path.exists()
    assert recovered_path.name == "secret.txt"

    # ---------------------------------------------------------
    # Verify recovered content
    # ---------------------------------------------------------

    recovered_data = recovered_path.read_bytes()

    assert recovered_data == original_data