"""
Tests for GhostWire CLI capacity command, --force flag, and explicit output filenames.
"""

from pathlib import Path
from PIL import Image
import pytest
import wave
import struct

from core.stego_service import StegoService
from core.validation import ValidationError
from ghostwire import build_parser, run_capacity


def create_sample_png(path: Path) -> Path:
    img = Image.new("RGB", (100, 100), (200, 100, 50))
    img.save(path, format="PNG")
    return path


def create_sample_wav(path: Path) -> Path:
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(struct.pack("<2000h", *range(2000)))
    return path


def test_capacity_query_png(tmp_path: Path):
    carrier = create_sample_png(tmp_path / "carrier.png")
    service = StegoService()
    info = service.get_capacity(carrier)

    assert info["type"] == "Image"
    assert info["format"] == "PNG"
    assert info["width"] == 100
    assert info["height"] == 100
    assert info["capacity_bits"] == 100 * 100 * 3
    assert info["capacity_bytes"] == (100 * 100 * 3) // 8


def test_capacity_query_wav(tmp_path: Path):
    carrier = create_sample_wav(tmp_path / "carrier.wav")
    service = StegoService()
    info = service.get_capacity(carrier)

    assert info["type"] == "Audio"
    assert info["format"] == "WAV"
    assert info["channels"] == 2
    assert info["capacity_bits"] == 2000


def test_capacity_cli_command(tmp_path: Path, capsys):
    carrier = create_sample_png(tmp_path / "carrier.png")
    parser = build_parser()
    args = parser.parse_args(["capacity", "-c", str(carrier)])

    ret = run_capacity(args)
    assert ret == 0

    captured = capsys.readouterr()
    assert "Carrier File:" in captured.out
    assert "Steganographic Capacity" in captured.out
    assert "30,000 bits" in captured.out


def test_embed_force_flag(tmp_path: Path):
    payload = tmp_path / "msg.txt"
    payload.write_bytes(b"Top Secret Force Test")
    carrier = create_sample_png(tmp_path / "carrier.png")
    stego_out = tmp_path / "stego.png"

    # Pre-create output file to test overwrite prevention
    stego_out.write_bytes(b"Existing content")

    service = StegoService()

    # Without force, it must raise ValidationError
    with pytest.raises(ValidationError, match="Use --force to overwrite"):
        service.embed(payload, carrier, stego_out, "password", force=False)

    # With force, it must succeed
    result = service.embed(payload, carrier, stego_out, "password", force=True)
    assert result == stego_out
    assert stego_out.stat().st_size > len(b"Existing content")


def test_extract_to_explicit_file_with_force(tmp_path: Path):
    payload = tmp_path / "original.txt"
    payload.write_bytes(b"Explicit filename payload recovery.")
    carrier = create_sample_png(tmp_path / "carrier.png")
    stego_out = tmp_path / "stego.png"

    service = StegoService()
    service.embed(payload, carrier, stego_out, "password")

    explicit_dest = tmp_path / "custom_named_secret.dat"

    # Extract directly to explicit filename
    recovered = service.extract(
        carrier_path=stego_out,
        output_directory=explicit_dest,
        password="password",
    )

    assert recovered == explicit_dest
    assert recovered.read_bytes() == b"Explicit filename payload recovery."

    # Extract again to existing file without force -> should raise ValueError
    with pytest.raises(ValueError, match="Use --force to overwrite"):
        service.extract(
            carrier_path=stego_out,
            output_directory=explicit_dest,
            password="password",
            force=False,
        )

    # With force -> succeeds
    recovered_force = service.extract(
        carrier_path=stego_out,
        output_directory=explicit_dest,
        password="password",
        force=True,
    )
    assert recovered_force == explicit_dest
