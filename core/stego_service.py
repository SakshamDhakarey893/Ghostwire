"""
GhostWire high-level steganography service.

Coordinates payload processing, invariant carrier fingerprinting,
salted position randomization, and carrier LSB embedding/extraction.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.audio_stego import AudioStego
from core.image_stego import ImageStego
from core.packet import HEADER_SIZE_V1, HEADER_SIZE_V2, PacketHeader
from core.payload import PayloadProcessor
from core.randomizer import Randomizer

from .validation import (
    validate_carrier,
    validate_output_path,
    validate_password,
    validate_payload,
)


def get_carrier_engine(carrier_path: Path | str) -> ImageStego | AudioStego:
    """Return the appropriate steganography engine for the carrier file."""
    path = Path(carrier_path)
    ext = path.suffix.lower()
    if ext == ".png":
        return ImageStego(path)
    if ext == ".wav":
        return AudioStego(path)
    raise ValueError(
        f"Unsupported carrier format '{ext}'. Supported formats: .png, .wav"
    )


class StegoService:
    """High-level GhostWire embed/extract/capacity service."""

    def get_capacity(self, carrier_path: str | Path) -> dict[str, Any]:
        """
        Query carrier capacity and metadata.

        Args:
            carrier_path: Path to PNG or WAV carrier.

        Returns:
            Dictionary with carrier type, dimensions/channels, and capacity metrics.
        """
        carrier_path = Path(carrier_path)
        if not carrier_path.is_file():
            raise FileNotFoundError(f"Carrier file not found: {carrier_path}")

        validate_carrier(carrier_path)
        stego = get_carrier_engine(carrier_path)
        return stego.get_carrier_info(carrier_path)

    def embed(
        self,
        payload_path: str | Path,
        carrier_path: str | Path,
        output_path: str | Path,
        password: str,
        force: bool = False,
        show_progress: bool = True,
        verbose: bool = False,
    ) -> Path:
        """
        Embed a payload file into a digital carrier (PNG or WAV).

        Security Pipeline:
            file -> SHA-256 -> zlib -> AES-256-GCM -> metadata -> v2 header (with salt)
            carrier -> invariant MSB fingerprint -> header positions (pwd + fp)
            salt -> payload positions (pwd + fp + salt, excluding header)
            -> LSB embedding -> stego carrier
        """
        payload_path = Path(payload_path)
        carrier_path = Path(carrier_path)
        output_path = Path(output_path)

        if not payload_path.is_file():
            raise FileNotFoundError(f"Payload file not found: {payload_path}")

        if not carrier_path.is_file():
            raise FileNotFoundError(f"Carrier file not found: {carrier_path}")

        validate_payload(payload_path)
        validate_carrier(carrier_path)
        validate_output_path(output_path, carrier_path, force=force)
        validate_password(password)

        stego = get_carrier_engine(carrier_path)
        capacity = stego.calculate_capacity(carrier_path)

        processor = PayloadProcessor(password)
        prepared = processor.prepare(payload_path)

        header_bytes = prepared.packet[:HEADER_SIZE_V2]
        body = prepared.packet[HEADER_SIZE_V2:]
        header = PacketHeader.deserialize(header_bytes)

        header_bits = len(header_bytes) * 8
        body_bits = len(body) * 8
        total_required_bits = header_bits + body_bits

        if total_required_bits > capacity:
            req_kb = round(total_required_bits / (8 * 1024), 2)
            cap_kb = round(capacity / (8 * 1024), 2)
            raise ValueError(
                f"Carrier capacity exceeded: payload packet requires {total_required_bits} bits "
                f"({req_kb} KB), but carrier only holds {capacity} bits ({cap_kb} KB)."
            )

        # 1. Derive invariant carrier fingerprint (LSB-masked)
        carrier_fingerprint = stego.calculate_fingerprint(carrier_path)

        # 2. Derive non-colliding header positions from (password + carrier_fingerprint)
        header_randomizer = Randomizer(
            password=password,
            carrier_fingerprint=carrier_fingerprint,
        )
        header_positions = header_randomizer.generate_positions(
            total_pixels=capacity,
            required_bits=header_bits,
        )

        # 3. Derive body positions from (password + carrier_fingerprint + random salt)
        # Excludes header positions to guarantee zero collisions
        body_randomizer = Randomizer(
            password=password,
            carrier_fingerprint=carrier_fingerprint,
            salt=header.salt,
        )
        body_positions = body_randomizer.generate_positions(
            total_pixels=capacity,
            required_bits=body_bits,
            exclude_positions=header_positions,
        )

        if verbose:
            print(f"[*] Carrier capacity: {capacity} bits ({(capacity // 8):,} bytes)")
            print(f"[*] Carrier fingerprint: {carrier_fingerprint.hex()[:16]}...")
            print(f"[*] Random position salt: {header.salt.hex()}")
            print(f"[*] Header bits: {header_bits}, Body bits: {body_bits}")

        # Combined sequential stream and positions
        all_data = header_bytes + body
        all_positions = header_positions + body_positions

        stego.embed(
            data=all_data,
            positions=all_positions,
            output_path=output_path,
            show_progress=show_progress,
        )

        return output_path

    def extract(
        self,
        carrier_path: str | Path,
        output_directory: str | Path,
        password: str,
        force: bool = False,
        show_progress: bool = True,
        verbose: bool = False,
    ) -> Path:
        """
        Extract and decrypt a payload from a GhostWire carrier.

        Parameters
        ----------
        carrier_path:
            Path to the stego PNG or WAV carrier.
        output_directory:
            Directory or specific filename where the recovered payload will be written.
        password:
            Password used during embedding.
        force:
            Allow overwriting the output file if it exists.
        show_progress:
            Show progress bar for large payloads.
        verbose:
            Print diagnostic details.
        """
        carrier_path = Path(carrier_path)
        output_target = Path(output_directory)

        if not carrier_path.is_file():
            raise FileNotFoundError(f"Carrier file not found: {carrier_path}")

        validate_carrier(carrier_path)
        validate_password(password)

        stego = get_carrier_engine(carrier_path)
        capacity = stego.calculate_capacity(carrier_path)

        carrier_fingerprint = stego.calculate_fingerprint(carrier_path)

        # ---------------------------------------------------------
        # Step 1: Recover bootstrap header
        # ---------------------------------------------------------
        header_bits_v2 = HEADER_SIZE_V2 * 8

        if header_bits_v2 > capacity:
            raise ValueError("Carrier is too small to contain a GhostWire header.")

        header_randomizer = Randomizer(
            password=password,
            carrier_fingerprint=carrier_fingerprint,
        )
        header_positions = header_randomizer.generate_positions(
            total_pixels=capacity,
            required_bits=header_bits_v2,
        )

        header_data = stego.extract(
            bit_count=header_bits_v2,
            positions=header_positions,
        )

        try:
            header = PacketHeader.deserialize(header_data)
        except ValueError:
            # Check for legacy v1 fallback
            try:
                v1_pos = Randomizer(password).generate_positions(
                    capacity, HEADER_SIZE_V1 * 8
                )
                v1_data = stego.extract(HEADER_SIZE_V1 * 8, v1_pos)
                header = PacketHeader.deserialize(v1_data)
            except Exception as exc:
                raise ValueError(
                    "Extraction failed: invalid GhostWire header. "
                    "Verify that the correct password and carrier file were provided."
                ) from exc

        if verbose:
            print(f"[*] Carrier capacity: {capacity} bits ({(capacity // 8):,} bytes)")
            print(f"[*] Carrier fingerprint: {carrier_fingerprint.hex()[:16]}...")
            print(f"[*] GhostWire Protocol Version: {header.version}")
            if header.version == 2:
                print(f"[*] Extracted position salt: {header.salt.hex()}")
            print(f"[*] Encrypted body size: {header.packet_size:,} bytes")

        # ---------------------------------------------------------
        # Step 2: Extract body bits using version-appropriate randomizer
        # ---------------------------------------------------------
        body_bits = header.packet_size * 8
        total_packet_bits = (header.header_size + header.packet_size) * 8

        if total_packet_bits > capacity:
            raise ValueError(
                f"Corrupted packet: declared size ({total_packet_bits} bits) "
                f"exceeds carrier capacity ({capacity} bits)."
            )

        if header.version == 2:
            body_randomizer = Randomizer(
                password=password,
                carrier_fingerprint=carrier_fingerprint,
                salt=header.salt,
            )
            body_positions = body_randomizer.generate_positions(
                total_pixels=capacity,
                required_bits=body_bits,
                exclude_positions=header_positions,
            )
            body_data = stego.extract(
                bit_count=body_bits,
                positions=body_positions,
                show_progress=show_progress,
            )
            packet = header_data[:HEADER_SIZE_V2] + body_data
        else:
            # v1 legacy fallback: sequential randomizer
            all_v1_positions = Randomizer(password).generate_positions(
                total_pixels=capacity,
                required_bits=total_packet_bits,
            )
            packet = stego.extract(
                bit_count=total_packet_bits,
                positions=all_v1_positions,
                show_progress=show_progress,
            )

        # ---------------------------------------------------------
        # Step 3: Decrypt and decompress the payload
        # ---------------------------------------------------------
        processor = PayloadProcessor(password)
        try:
            recovered = processor.recover(packet)
        except Exception as exc:
            raise ValueError(
                "Payload decryption/verification failed. "
                "Possible wrong password, tampered carrier, or corrupted data."
            ) from exc

        # ---------------------------------------------------------
        # Step 4: Write recovered payload
        # ---------------------------------------------------------
        # Support both directory target and explicit output file path
        if (
            output_target.is_dir()
            or str(output_directory).endswith(("/", "\\"))
            or not output_target.suffix
        ):
            output_target.mkdir(parents=True, exist_ok=True)
            destination = output_target / recovered.filename
        else:
            output_target.parent.mkdir(parents=True, exist_ok=True)
            destination = output_target

        if destination.exists() and not force:
            raise ValueError(
                f"Output file already exists: {destination}. Use --force to overwrite."
            )

        destination.write_bytes(recovered.data)
        return destination