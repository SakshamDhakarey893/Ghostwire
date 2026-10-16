"""
GhostWire WAV audio steganography engine.

Implements randomized LSB embedding and extraction for uncompressed
PCM audio files (WAV).
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence
import wave

from core.utils import bits_to_bytes, bytes_to_bits


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

    def embed(
        self,
        data: bytes,
        positions: Sequence[int],
        output_path: str | Path,
    ) -> None:
        """
        Embed binary data into randomized sample LSB positions.

        Args:
            data: Binary payload to embed.
            positions: Sequence of unique sample indices.
            output_path: Destination path for the stego WAV file.

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
            raise ValueError("Not enough carrier capacity for payload.")

        sampwidth = params.sampwidth
        for bit, sample_index in zip(bits, positions):
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
    ) -> bytes:
        """
        Extract binary data from selected sample LSB positions.

        Args:
            bit_count: Number of bits to recover (must be divisible by 8).
            positions: Sequence of sample positions.

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
            raise ValueError("Not enough positions for requested extraction.")

        params, raw_frames = self._load_audio(self.audio_path)
        total_samples = params.nframes * params.nchannels
        sampwidth = params.sampwidth

        bits: list[int] = []
        for sample_index in positions[:bit_count]:
            if sample_index < 0 or sample_index >= total_samples:
                raise ValueError(
                    f"Sample position {sample_index} is out of bounds for audio carrier."
                )

            byte_index = sample_index * sampwidth
            bits.append(raw_frames[byte_index] & 1)

        return bits_to_bytes(bits)
