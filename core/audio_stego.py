"""
GhostWire WAV audio steganography engine.

Implements randomized LSB embedding and extraction for uncompressed
PCM audio files (WAV).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Sequence
import wave

import numpy as np
from tqdm import tqdm

from core.utils import bits_to_bytes, bytes_to_bits

# Minimum bits required to trigger live CLI progress bar (50 KB payload).
PROGRESS_THRESHOLD_BITS = 50 * 1024 * 8


class AudioStego:
    """Embed and extract binary data inside WAV audio using randomized LSB."""

    def __init__(self, audio_path: str | Path):
        self.audio_path = Path(audio_path)

    @staticmethod
    def _load_audio(audio_path: Path) -> tuple[wave._wave_params, bytearray]:
        """
        Open a WAV audio file and return its parameters and raw sample bytes.

        Raises:
            ValueError: If file is not a valid uncompressed PCM WAV.
            FileNotFoundError: If the file does not exist.
        """
        if not audio_path.is_file():
            raise FileNotFoundError(f"Audio file not found: {audio_path}")

        if audio_path.suffix.lower() != ".wav":
            raise ValueError("GhostWire audio steganography supports .wav format only.")

        try:
            with wave.open(str(audio_path), "rb") as wave_file:
                params = wave_file.getparams()
                if params.comptype != "NONE":
                    raise ValueError(
                        f"Unsupported WAV compression '{params.comptype}'. "
                        "Only uncompressed PCM WAV files are supported."
                    )

                if params.sampwidth not in (1, 2, 3, 4):
                    raise ValueError(
                        f"Unsupported sample width: {params.sampwidth} bytes. "
                        "Supported bit depths are 8-bit, 16-bit, 24-bit, and 32-bit PCM."
                    )

                raw_frames = bytearray(wave_file.readframes(params.nframes))
                return params, raw_frames
        except wave.Error as exc:
            raise ValueError(f"Invalid or corrupted WAV file: {exc}") from exc

    @staticmethod
    def calculate_capacity(audio_path: str | Path) -> int:
        """
        Calculate available payload capacity in bits.

        One bit is embedded per audio sample (across all audio channels).
        Total capacity = n_frames * n_channels.
        """
        audio_path = Path(audio_path)
        params, _ = AudioStego._load_audio(audio_path)
        return params.nframes * params.nchannels

    @staticmethod
    def calculate_fingerprint(audio_path: str | Path) -> bytes:
        """
        Calculate an invariant SHA-256 fingerprint from WAV audio metadata and MSBs.

        By zeroing out the least significant bit (LSB) of each sample, the
        fingerprint is guaranteed to be byte-for-byte identical before embedding
        and after embedding.
        """
        params, raw_frames = AudioStego._load_audio(Path(audio_path))
        hasher = hashlib.sha256()
        hasher.update(
            f"AUD:{params.nchannels}:{params.sampwidth}:{params.framerate}:{params.nframes}".encode(
                "utf-8"
            )
        )
        arr = np.frombuffer(raw_frames, dtype=np.uint8).copy()
        # In little-endian PCM, sample LSB is at index [i * sampwidth]. Mask it out.
        arr[:: params.sampwidth] &= 0xFE
        hasher.update(arr.tobytes())
        return hasher.digest()

    @staticmethod
    def get_carrier_info(audio_path: str | Path) -> dict[str, str | int | float]:
        """Return descriptive metadata and capacity metrics for the audio carrier."""
        params, _ = AudioStego._load_audio(Path(audio_path))
        total_samples = params.nframes * params.nchannels
        duration = (
            round(params.nframes / params.framerate, 2)
            if params.framerate > 0
            else 0.0
        )
        return {
            "type": "Audio",
            "format": "WAV",
            "channels": params.nchannels,
            "sample_width": params.sampwidth * 8,
            "framerate": params.framerate,
            "frames": params.nframes,
            "duration_seconds": duration,
            "capacity_bits": total_samples,
            "capacity_bytes": total_samples // 8,
        }

    def embed(
        self,
        data: bytes,
        positions: Sequence[int],
        output_path: str | Path,
        show_progress: bool = False,
    ) -> None:
        """
        Embed binary data into randomized sample LSB positions.

        Args:
            data: Binary payload to embed.
            positions: Sequence of unique sample indices.
            output_path: Destination path for the stego WAV file.
            show_progress: Whether to show live progress bar for large payloads.

        Raises:
            ValueError: If capacity is insufficient or output path is invalid.
        """
        output_path = Path(output_path)
        if output_path.suffix.lower() != ".wav":
            raise ValueError("Output file must have a .wav extension.")

        params, raw_frames = self._load_audio(self.audio_path)
        bits = bytes_to_bits(data)
        total_samples = params.nframes * params.nchannels

        if len(bits) > len(positions):
            raise ValueError(
                f"Not enough carrier capacity for payload. Required: {len(bits)} bits, "
                f"available positions: {len(positions)} bits."
            )

        sampwidth = params.sampwidth
        use_progress = show_progress and (len(bits) >= PROGRESS_THRESHOLD_BITS)
        iterator = (
            tqdm(
                zip(bits, positions),
                total=len(bits),
                desc="[>] Embedding audio bits",
                unit="bit",
                unit_scale=True,
                leave=False,
            )
            if use_progress
            else zip(bits, positions)
        )

        for bit, sample_index in iterator:
            if sample_index < 0 or sample_index >= total_samples:
                raise ValueError(
                    f"Sample position {sample_index} is out of bounds for audio carrier."
                )

            # In little-endian PCM, byte (sample_index * sampwidth) holds the sample's LSB.
            byte_index = sample_index * sampwidth
            raw_frames[byte_index] = (raw_frames[byte_index] & 0xFE) | bit

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with wave.open(str(output_path), "wb") as out_wave:
            out_wave.setparams(params)
            out_wave.writeframes(raw_frames)

    def extract(
        self,
        bit_count: int,
        positions: Sequence[int],
        show_progress: bool = False,
    ) -> bytes:
        """
        Extract binary data from selected sample LSB positions.

        Args:
            bit_count: Number of bits to recover (must be divisible by 8).
            positions: Sequence of sample positions.
            show_progress: Whether to show live progress bar for large payloads.

        Returns:
            Recovered bytes.

        Raises:
            ValueError: If bit count is invalid or exceeds available positions.
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

        params, raw_frames = self._load_audio(self.audio_path)
        total_samples = params.nframes * params.nchannels
        sampwidth = params.sampwidth

        use_progress = show_progress and (bit_count >= PROGRESS_THRESHOLD_BITS)
        pos_slice = positions[:bit_count]
        iterator = (
            tqdm(
                pos_slice,
                total=bit_count,
                desc="[<] Extracting audio bits",
                unit="bit",
                unit_scale=True,
                leave=False,
            )
            if use_progress
            else pos_slice
        )

        bits: list[int] = []
        for sample_index in iterator:
            if sample_index < 0 or sample_index >= total_samples:
                raise ValueError(
                    f"Sample position {sample_index} is out of bounds for audio carrier."
                )

            byte_index = sample_index * sampwidth
            bits.append(raw_frames[byte_index] & 1)

        return bits_to_bytes(bits)
