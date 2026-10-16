"""
GhostWire PNG steganography engine.

Implements randomized LSB embedding and extraction.
"""

from pathlib import Path
from typing import Sequence

from PIL import Image


class ImageStego:
    """Embed and extract binary data using randomized LSB."""

    def __init__(self, image_path: str | Path):
        self.image_path = Path(image_path)

    @staticmethod
    def _load_image(image_path: Path) -> Image.Image:
        """Load a PNG image and normalize it to RGB/RGBA."""
        image = Image.open(image_path)

        if image.format != "PNG":
            raise ValueError("GhostWire currently supports PNG only.")

        if image.mode not in ("RGB", "RGBA"):
            image = image.convert("RGBA")

        return image

    @staticmethod
    def _bytes_to_bits(data: bytes) -> list[int]:
        """Convert bytes into a list of individual bits."""
        bits: list[int] = []

        for byte in data:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)

        return bits

    @staticmethod
    def _bits_to_bytes(bits: Sequence[int]) -> bytes:
        """Convert a sequence of bits back into bytes."""

        if len(bits) % 8 != 0:
            raise ValueError("Bit sequence length must be divisible by 8.")

        output = bytearray()

        for index in range(0, len(bits), 8):
            byte = 0

            for bit in bits[index:index + 8]:
                if bit not in (0, 1):
                    raise ValueError("Bits must contain only 0 or 1.")

                byte = (byte << 1) | bit

            output.append(byte)

        return bytes(output)

    @staticmethod
    def calculate_capacity(image_path: str | Path) -> int:
        """
        Calculate the number of payload bits available.

        One LSB is available per RGB/RGBA channel.
        Alpha is intentionally excluded from embedding.
        """

        image = ImageStego._load_image(Path(image_path))

        width, height = image.size

        # Three color channels per pixel.
        return width * height * 3

    @staticmethod
    def _channel_positions(
        image: Image.Image,
    ) -> list[tuple[int, int, int]]:
        """
        Return RGB channel positions.

        Each tuple contains:

            (x, y, channel_index)

        Alpha is never modified.
        """

        width, height = image.size

        positions = []

        for y in range(height):
            for x in range(width):
                for channel in range(3):
                    positions.append((x, y, channel))

        return positions

    def embed(
        self,
        data: bytes,
        positions: Sequence[int],
        output_path: str | Path,
    ) -> None:
        """
        Embed data into selected RGB channel positions.

        Args:
            data: Bytes to hide.
            positions: Randomized channel positions.
            output_path: Destination PNG path.
        """

        image = self._load_image(self.image_path)

        bits = self._bytes_to_bits(data)

        if len(bits) > len(positions):
            raise ValueError(
                "Not enough carrier capacity for payload."
            )

        pixels = image.load()
        channel_positions = self._channel_positions(image)

        for bit, position_index in zip(bits, positions):
            x, y, channel = channel_positions[position_index]

            pixel = list(pixels[x, y])

            # Replace only the least significant bit.
            pixel[channel] = (
                pixel[channel] & 0xFE
            ) | bit

            pixels[x, y] = tuple(pixel)

        output_path = Path(output_path)

        if output_path.suffix.lower() != ".png":
            raise ValueError("Output file must have a .png extension.")

        image.save(output_path, format="PNG")

    def extract(
        self,
        bit_count: int,
        positions: Sequence[int],
    ) -> bytes:
        """
        Extract bytes from selected RGB channel positions.

        Args:
            bit_count: Number of bits to extract.
            positions: Randomized channel positions.

        Returns:
            Extracted bytes.
        """

        if bit_count < 0:
            raise ValueError("Bit count cannot be negative.")

        if bit_count % 8 != 0:
            raise ValueError(
                "Bit count must be divisible by 8."
            )

        if bit_count > len(positions):
            raise ValueError(
                "Not enough positions for requested extraction."
            )

        image = self._load_image(self.image_path)
        pixels = image.load()
        channel_positions = self._channel_positions(image)

        bits = []

        for position_index in positions[:bit_count]:
            x, y, channel = channel_positions[position_index]

            pixel = pixels[x, y]

            bits.append(pixel[channel] & 1)

        return self._bits_to_bytes(bits)