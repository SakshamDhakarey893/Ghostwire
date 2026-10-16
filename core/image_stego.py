"""
GhostWire PNG steganography engine.

Implements high-performance randomized LSB embedding and extraction
for PNG images.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Sequence

import numpy as np
from PIL import Image
from tqdm import tqdm

from core.utils import bits_to_bytes, bytes_to_bits

# Minimum bits required to trigger live CLI progress bar (50 KB payload).
PROGRESS_THRESHOLD_BITS = 50 * 1024 * 8


class ImageStego:
    """Embed and extract binary data using randomized LSB in PNG carriers."""

    def __init__(self, image_path: str | Path):
        self.image_path = Path(image_path)

    @staticmethod
    def _load_image(image_path: Path) -> Image.Image:
        """Load a PNG image and normalize it to RGB/RGBA."""
        if not image_path.is_file():
            raise FileNotFoundError(f"Carrier image not found: {image_path}")

        image = Image.open(image_path)

        if image.format != "PNG":
            raise ValueError("GhostWire currently supports PNG only.")

        if image.mode not in ("RGB", "RGBA"):
            image = image.convert("RGBA")

        return image

    @staticmethod
    def _bytes_to_bits(data: bytes) -> list[int]:
        """Convert bytes into a list of individual bits."""
        return bytes_to_bits(data)

    @staticmethod
    def _bits_to_bytes(bits: Sequence[int]) -> bytes:
        """Convert a sequence of bits back into bytes."""
        return bits_to_bytes(bits)

    @staticmethod
    def calculate_capacity(image_path: str | Path) -> int:
        """
        Calculate the number of payload bits available.

        One LSB is available per RGB/RGBA channel.
        Alpha is intentionally excluded from embedding.
        """
        image = ImageStego._load_image(Path(image_path))
        width, height = image.size
        # Three color channels per pixel (RGB).
        return width * height * 3

    @staticmethod
    def index_to_coord(position_index: int, width: int) -> tuple[int, int, int]:
        """
        Convert a 1D channel position index to (x, y, channel) in O(1) time.

        Avoids allocating multi-gigabyte lists of coordinate tuples.
        """
        channel = position_index % 3
        pixel_index = position_index // 3
        x = pixel_index % width
        y = pixel_index // width
        return x, y, channel

    @staticmethod
    def _channel_positions(
        image: Image.Image,
    ) -> list[tuple[int, int, int]]:
        """
        Return RGB channel positions list (retained for backward compatibility).
        """
        width, height = image.size
        positions = []
        for y in range(height):
            for x in range(width):
                for channel in range(3):
                    positions.append((x, y, channel))
        return positions

    @staticmethod
    def calculate_fingerprint(image_path: str | Path) -> bytes:
        """
        Calculate an invariant SHA-256 fingerprint from carrier metadata and MSBs.

        By zeroing out the least significant bit (LSB) of each channel, the
        fingerprint is guaranteed to be byte-for-byte identical before embedding
        and after embedding.
        """
        image = ImageStego._load_image(Path(image_path))
        width, height = image.size

        hasher = hashlib.sha256()
        hasher.update(f"IMG:{width}x{height}:{image.mode}".encode("utf-8"))

        arr = np.array(image)[..., :3]
        # Mask out LSB to ensure invariance under LSB modification
        msb_data = (arr & 0xFE).tobytes()
        hasher.update(msb_data)
        return hasher.digest()

    @staticmethod
    def get_carrier_info(image_path: str | Path) -> dict[str, str | int]:
        """Return human-readable metadata and capacity metrics for the image."""
        image = ImageStego._load_image(Path(image_path))
        w, h = image.size
        cap_bits = w * h * 3
        return {
            "type": "Image",
            "format": "PNG",
            "width": w,
            "height": h,
            "mode": image.mode,
            "channels": 3,
            "capacity_bits": cap_bits,
            "capacity_bytes": cap_bits // 8,
        }

    def embed(
        self,
        data: bytes,
        positions: Sequence[int],
        output_path: str | Path,
        show_progress: bool = False,
    ) -> None:
        """
        Embed data into selected RGB channel positions using fast index arithmetic.

        Args:
            data: Bytes to hide.
            positions: Randomized channel positions.
            output_path: Destination PNG path.
            show_progress: Whether to show live progress bar for large payloads.
        """
        image = self._load_image(self.image_path)
        bits = self._bytes_to_bits(data)
        width, height = image.size
        capacity = width * height * 3

        if len(bits) > len(positions):
            raise ValueError(
                f"Not enough carrier capacity for payload. Required: {len(bits)} bits, "
                f"available positions: {len(positions)} bits."
            )

        output_path = Path(output_path)
        if output_path.suffix.lower() != ".png":
            raise ValueError("Output file must have a .png extension.")

        pixels = image.load()
        use_progress = show_progress and (len(bits) >= PROGRESS_THRESHOLD_BITS)
        iterator = (
            tqdm(
                zip(bits, positions),
                total=len(bits),
                desc="[>] Embedding bits",
                unit="bit",
                unit_scale=True,
                leave=False,
            )
            if use_progress
            else zip(bits, positions)
        )

        for bit, position_index in iterator:
            if position_index < 0 or position_index >= capacity:
                raise ValueError(
                    f"Position index {position_index} is out of bounds for carrier."
                )

            channel = position_index % 3
            pixel_index = position_index // 3
            x = pixel_index % width
            y = pixel_index // width

            pixel = list(pixels[x, y])
            pixel[channel] = (pixel[channel] & 0xFE) | bit
            pixels[x, y] = tuple(pixel)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        image.save(output_path, format="PNG")

    def extract(
        self,
        bit_count: int,
        positions: Sequence[int],
        show_progress: bool = False,
    ) -> bytes:
        """
        Extract bytes from selected RGB channel positions using fast index arithmetic.

        Args:
            bit_count: Number of bits to extract.
            positions: Randomized channel positions.
            show_progress: Whether to show live progress bar for large payloads.

        Returns:
            Extracted bytes.
        """
        if bit_count < 0:
            raise ValueError("Bit count cannot be negative.")

        if bit_count % 8 != 0:
            raise ValueError("Bit count must be divisible by 8.")

        if bit_count > len(positions):
            raise ValueError(
                f"Not enough positions for requested extraction. "
                f"Requested: {bit_count} bits, available: {len(positions)} bits."
            )

        image = self._load_image(self.image_path)
        width, height = image.size
        capacity = width * height * 3
        pixels = image.load()

        use_progress = show_progress and (bit_count >= PROGRESS_THRESHOLD_BITS)
        pos_slice = positions[:bit_count]
        iterator = (
            tqdm(
                pos_slice,
                total=bit_count,
                desc="[<] Extracting bits",
                unit="bit",
                unit_scale=True,
                leave=False,
            )
            if use_progress
            else pos_slice
        )

        bits: list[int] = []
        for position_index in iterator:
            if position_index < 0 or position_index >= capacity:
                raise ValueError(
                    f"Position index {position_index} is out of bounds for carrier."
                )

            channel = position_index % 3
            pixel_index = position_index // 3
            x = pixel_index % width
            y = pixel_index // width

            bits.append(pixels[x, y][channel] & 1)

        return self._bits_to_bytes(bits)