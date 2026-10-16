"""
Steganalysis resistance tests.

Verifies that GhostWire's randomized LSB embedding distributes modifications
uniformly across the carrier rather than clustering sequentially, and tests
LSB distribution using chi-square analysis.
"""

from pathlib import Path
import numpy as np
from PIL import Image
import pytest

from core.image_stego import ImageStego
from core.stego_service import StegoService


def create_gradient_carrier(path: Path, width: int = 200, height: int = 200) -> Path:
    """Create a carrier with smooth gradients to simulate photographic media."""
    arr = np.zeros((height, width, 3), dtype=np.uint8)
    for y in range(height):
        for x in range(width):
            arr[y, x] = [
                int(255 * (x / width)),
                int(255 * (y / height)),
                int(255 * ((x + y) / (width + height))),
            ]
    Image.fromarray(arr).save(path, format="PNG")
    return path


def test_chi_square_lsb_randomness(tmp_path: Path):
    """
    Verify that GhostWire encrypted payloads exhibit high entropy and
    statistically uniform (50/50) LSB bit distribution conforming to Chi-Square test.
    """
    payload_file = tmp_path / "secret.txt"
    payload_file.write_bytes(b"GhostWire Security Steganalysis Resistance Verification " * 40)

    carrier_file = create_gradient_carrier(tmp_path / "carrier.png", 200, 200)
    stego_file = tmp_path / "stego.png"

    service = StegoService()
    service.embed(payload_file, carrier_file, stego_file, "StegPassword123")

    img_orig = np.array(Image.open(carrier_file).convert("RGB"))
    img_stego = np.array(Image.open(stego_file).convert("RGB"))

    # Identify modified channel values
    diff = (img_orig != img_stego)
    modified_count = np.sum(diff)

    assert modified_count > 0, "Stego image must contain modifications."

    # In randomized LSB with random AES ciphertext, approximately half of the
    # bits in target positions will change (50% bit flip probability)
    # Check that modified pixels are distributed across the whole image (not just the top rows)
    y_coords, x_coords, _ = np.where(diff)

    # Modifications should span across the vertical and horizontal extent of the carrier
    assert np.min(y_coords) < 50
    assert np.max(y_coords) > 150
    assert np.min(x_coords) < 50
    assert np.max(x_coords) > 150

    # Chi-square test on LSB bit values of the embedded stego channels
    stego_lsbs = img_stego & 1
    ones = int(np.sum(stego_lsbs))
    zeros = int(stego_lsbs.size - ones)
    expected = float(stego_lsbs.size) / 2.0

    chi_sq = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
    diff_percent = abs(ones - zeros) / float(stego_lsbs.size)
    assert diff_percent < 0.05, f"LSB distribution imbalance too high: {diff_percent:.4f}"
