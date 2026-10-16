"""
Unit and integration tests for WAV audio steganography engine.
"""

from pathlib import Path
import struct
import wave

import pytest

from core.audio_stego import AudioStego
from core.randomizer import Randomizer
from core.stego_service import StegoService


def create_test_wav(
    path: Path,
    n_channels: int = 1,
    sampwidth: int = 2,
    framerate: int = 44100,
    n_frames: int = 2000,
) -> Path:
    """Helper to generate a synthetic uncompressed PCM WAV carrier."""
    path = Path(path)
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(n_channels)
        wf.setsampwidth(sampwidth)
        wf.setframerate(framerate)

        total_samples = n_frames * n_channels
        if sampwidth == 1:
            # 8-bit unsigned PCM (0..255)
            data = bytes([(i * 7) % 256 for i in range(total_samples)])
        elif sampwidth == 2:
            # 16-bit signed PCM (-32768..32767)
            samples = [int(10000 * ((i % 100) / 50.0 - 1.0)) for i in range(total_samples)]
            data = struct.pack(f"<{total_samples}h", *samples)
        else:
            raise ValueError(f"Unsupported test sampwidth: {sampwidth}")

        wf.writeframes(data)
    return path


def test_audio_capacity_mono(tmp_path: Path):
    wav_path = create_test_wav(tmp_path / "mono.wav", n_channels=1, sampwidth=2, n_frames=1500)
    capacity = AudioStego.calculate_capacity(wav_path)
    assert capacity == 1500


def test_audio_capacity_stereo(tmp_path: Path):
    wav_path = create_test_wav(tmp_path / "stereo.wav", n_channels=2, sampwidth=2, n_frames=1000)
    capacity = AudioStego.calculate_capacity(wav_path)
    assert capacity == 2000


def test_audio_capacity_8bit(tmp_path: Path):
    wav_path = create_test_wav(tmp_path / "eight_bit.wav", n_channels=1, sampwidth=1, n_frames=800)
    capacity = AudioStego.calculate_capacity(wav_path)
    assert capacity == 800


def test_audio_embed_and_extract_roundtrip(tmp_path: Path):
    carrier = create_test_wav(tmp_path / "carrier.wav", n_channels=2, sampwidth=2, n_frames=2000)
    stego_out = tmp_path / "stego.wav"
    payload = b"GhostWire Audio Payload Secret"

    stego = AudioStego(carrier)
    capacity = stego.calculate_capacity(carrier)
    required_bits = len(payload) * 8

    positions = Randomizer("audio-key").generate_positions(capacity, required_bits)
    stego.embed(payload, positions, stego_out)

    assert stego_out.exists()
    extractor = AudioStego(stego_out)
    extracted = extractor.extract(required_bits, positions)
    assert extracted == payload


def test_audio_fidelity_preserved(tmp_path: Path):
    carrier = create_test_wav(tmp_path / "carrier.wav", n_channels=2, sampwidth=2, framerate=44100, n_frames=500)
    stego_out = tmp_path / "stego.wav"
    payload = b"Test 12345"

    stego = AudioStego(carrier)
    capacity = stego.calculate_capacity(carrier)
    required_bits = len(payload) * 8
    positions = Randomizer("pwd").generate_positions(capacity, required_bits)

    stego.embed(payload, positions, stego_out)

    with wave.open(str(carrier), "rb") as orig, wave.open(str(stego_out), "rb") as modified:
        assert orig.getparams() == modified.getparams()
        orig_frames = orig.readframes(orig.getnframes())
        mod_frames = modified.readframes(modified.getnframes())

        orig_samples = struct.unpack(f"<{len(orig_frames)//2}h", orig_frames)
        mod_samples = struct.unpack(f"<{len(mod_frames)//2}h", mod_frames)

        # Ensure modified audio samples differ by at most +/- 1 LSB
        for o, m in zip(orig_samples, mod_samples):
            assert abs(o - m) <= 1


def test_audio_wrong_positions_fail_recovery(tmp_path: Path):
    carrier = create_test_wav(tmp_path / "carrier.wav", n_channels=1, sampwidth=2, n_frames=1000)
    stego_out = tmp_path / "stego.wav"
    payload = b"TopSecretAudioData"

    stego = AudioStego(carrier)
    capacity = stego.calculate_capacity(carrier)
    required_bits = len(payload) * 8

    correct_pos = Randomizer("correct-key").generate_positions(capacity, required_bits)
    wrong_pos = Randomizer("wrong-key").generate_positions(capacity, required_bits)

    stego.embed(payload, correct_pos, stego_out)

    extractor = AudioStego(stego_out)
    extracted = extractor.extract(required_bits, wrong_pos)
    assert extracted != payload


def test_audio_payload_too_large(tmp_path: Path):
    carrier = create_test_wav(tmp_path / "small.wav", n_channels=1, sampwidth=2, n_frames=100)
    stego_out = tmp_path / "stego.wav"
    payload = b"X" * 200  # 1600 bits > 100 capacity

    stego = AudioStego(carrier)
    with pytest.raises(ValueError, match="Not enough carrier capacity"):
        stego.embed(payload, list(range(100)), stego_out)


def test_audio_invalid_extension(tmp_path: Path):
    carrier = create_test_wav(tmp_path / "carrier.wav", n_channels=1, sampwidth=2, n_frames=500)
    stego = AudioStego(carrier)
    with pytest.raises(ValueError, match="must have a .wav extension"):
        stego.embed(b"test", list(range(32)), tmp_path / "out.mp3")


def test_audio_full_service_embed_and_extract(tmp_path: Path):
    """End-to-end integration test of StegoService with WAV carrier."""
    service = StegoService()

    payload_file = tmp_path / "confidential.pdf"
    original_bytes = b"%PDF-1.4 GhostWire audio steganography full integration verification."
    payload_file.write_bytes(original_bytes)

    carrier = create_test_wav(
        tmp_path / "carrier.wav",
        n_channels=2,
        sampwidth=2,
        framerate=44100,
        n_frames=10000,
    )
    stego_wav = tmp_path / "stego_output.wav"
    output_dir = tmp_path / "extracted_dir"

    service.embed(
        payload_path=payload_file,
        carrier_path=carrier,
        output_path=stego_wav,
        password="audio-strong-password",
    )

    assert stego_wav.exists()

    recovered_path = service.extract(
        carrier_path=stego_wav,
        output_directory=output_dir,
        password="audio-strong-password",
    )

    assert recovered_path.exists()
    assert recovered_path.name == "confidential.pdf"
    assert recovered_path.read_bytes() == original_bytes


def test_audio_wrong_password_fails_extraction(tmp_path: Path):
    """Verifies that extracting audio stego with wrong password fails."""
    service = StegoService()

    payload_file = tmp_path / "secret.txt"
    payload_file.write_bytes(b"Top secret audio payload")
    carrier = create_test_wav(tmp_path / "carrier.wav", n_channels=2, sampwidth=2, n_frames=5000)
    stego_wav = tmp_path / "stego.wav"
    output_dir = tmp_path / "recovered"

    service.embed(
        payload_path=payload_file,
        carrier_path=carrier,
        output_path=stego_wav,
        password="correct-audio-pass",
    )

    with pytest.raises(Exception):
        service.extract(
            carrier_path=stego_wav,
            output_directory=output_dir,
            password="wrong-audio-pass",
        )
