"""
GhostWire high-level steganography service.

Connects payload processing, randomized positions,
and PNG LSB embedding/extraction.
"""

from pathlib import Path

from core.audio_stego import AudioStego
from core.image_stego import ImageStego
from core.packet import HEADER_SIZE, PacketHeader
from core.payload import PayloadProcessor
from core.randomizer import Randomizer

from .validation import (
    validate_carrier,
    validate_output_directory,
    validate_output_path,
    validate_password,
    validate_payload,
)


def get_carrier_engine(carrier_path: Path) -> ImageStego | AudioStego:
    """Return the appropriate steganography engine for the carrier file."""
    ext = carrier_path.suffix.lower()
    if ext == ".png":
        return ImageStego(carrier_path)
    if ext == ".wav":
        return AudioStego(carrier_path)
    raise ValueError(f"Unsupported carrier format: {ext}")


class StegoService:
    """High-level GhostWire embed/extract service."""

    def embed(
        self,
        payload_path: str | Path,
        carrier_path: str | Path,
        output_path: str | Path,
        password: str,
    ):
        """
        Embed a payload file into a PNG carrier.

        Parameters
        ----------
        payload_path:
            Path to the file that will be hidden.

        carrier_path:
            Path to the PNG carrier image.

        output_path:
            Path where the resulting stego image will be written.

        password:
            Password used for payload protection and
            randomized embedding positions.
        """

        payload_path = Path(payload_path)
        carrier_path = Path(carrier_path)
        output_path = Path(output_path)

        # Missing files should produce FileNotFoundError.
        if not payload_path.is_file():
            raise FileNotFoundError(
                f"Payload file not found: {payload_path}"
            )

        if not carrier_path.is_file():
            raise FileNotFoundError(
                f"Carrier image not found: {carrier_path}"
            )

        # Normal validation after existence checks.
        validate_payload(payload_path)
        validate_carrier(carrier_path)
        validate_output_path(
            output_path,
            carrier_path,
        )
        validate_password(password)

        processor = PayloadProcessor(password)

        prepared = processor.prepare(
            payload_path
        )

        packet = prepared.packet

        stego = get_carrier_engine(carrier_path)

        capacity = stego.calculate_capacity(
            carrier_path
        )

        required_bits = len(packet) * 8

        if required_bits > capacity:
            raise ValueError(
                "Carrier does not have enough capacity "
                "for the payload."
            )

        randomizer = Randomizer(password)

        positions = randomizer.generate_positions(
            total_pixels=capacity,
            required_bits=required_bits,
        )

        stego.embed(
            data=packet,
            positions=positions,
            output_path=output_path,
        )

        return output_path

    def extract(
        self,
        carrier_path: str | Path,
        output_directory: str | Path,
        password: str,
    ):
        """
        Extract a payload from a GhostWire PNG.

        Parameters
        ----------
        carrier_path:
            Path to the stego PNG image.

        output_directory:
            Directory where the recovered payload will be written.

        password:
            Password used during embedding.
        """

        carrier_path = Path(carrier_path)
        output_directory = Path(output_directory)

        # Missing carrier should produce FileNotFoundError.
        if not carrier_path.is_file():
            raise FileNotFoundError(
                f"Carrier image not found: {carrier_path}"
            )

        validate_carrier(carrier_path)
        validate_output_directory(output_directory)
        validate_password(password)

        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        stego = get_carrier_engine(carrier_path)

        capacity = stego.calculate_capacity(
            carrier_path
        )

        randomizer = Randomizer(password)

        # ---------------------------------------------------------
        # Step 1: Recover the fixed-size GhostWire header.
        # ---------------------------------------------------------

        header_bits = HEADER_SIZE * 8

        if header_bits > capacity:
            raise ValueError(
                "Carrier is too small to contain a "
                "GhostWire header."
            )

        header_positions = randomizer.generate_positions(
            total_pixels=capacity,
            required_bits=header_bits,
        )

        header_data = stego.extract(
            bit_count=header_bits,
            positions=header_positions,
        )

        header = PacketHeader.deserialize(
            header_data
        )

        # ---------------------------------------------------------
        # Step 2: Determine the complete packet size.
        # ---------------------------------------------------------

        total_packet_size = (
            HEADER_SIZE
            + header.packet_size
        )

        total_bits = total_packet_size * 8

        if total_bits > capacity:
            raise ValueError(
                "Packet size exceeds carrier capacity."
            )

        # ---------------------------------------------------------
        # Step 3: Generate the complete deterministic
        # randomized position sequence.
        # ---------------------------------------------------------

        all_positions = randomizer.generate_positions(
            total_pixels=capacity,
            required_bits=total_bits,
        )

        # ---------------------------------------------------------
        # Step 4: Extract the complete packet.
        # ---------------------------------------------------------

        packet = stego.extract(
            bit_count=total_bits,
            positions=all_positions,
        )

        # ---------------------------------------------------------
        # Step 5: Recover and decrypt/decompress the payload.
        # ---------------------------------------------------------

        processor = PayloadProcessor(password)

        recovered = processor.recover(
            packet
        )

        # ---------------------------------------------------------
        # Step 6: Write recovered payload.
        # ---------------------------------------------------------

        output_path = (
            output_directory
            / recovered.filename
        )

        output_path.write_bytes(
            recovered.data
        )

        return output_path