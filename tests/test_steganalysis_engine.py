"""
Unit tests for the GhostWire Steganalysis Engine.
"""

from pathlib import Path
from PIL import Image
import pytest
import wave
import struct

from core.steganalysis import Steganalyzer, SteganalysisReport


def create_test_image(path: Path) -> Path:
    img = Image.new("RGB", (120, 120), (140, 180, 220))
    img.save(path, format="PNG")
    return path


def create_test_audio(path: Path) -> Path:
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(struct.pack("<1000h", *range(1000)))
    return path


def test_analyze_image(tmp_path: Path):
    img_path = create_test_image(tmp_path / "test.png")
    report = Steganalyzer.analyze_carrier(img_path)

    assert isinstance(report, SteganalysisReport)
    assert report.media_type == "Image (PNG)"
    assert report.chi2_dof > 0
    assert 0.0 <= report.chi2_p_value <= 1.0
    assert 0.0 <= report.lsb_transition_rate <= 1.0
    assert 0.0 <= report.mean_chunk_entropy <= 1.0
    assert "verdict" in report.to_dict()


def test_analyze_audio(tmp_path: Path):
    wav_path = create_test_audio(tmp_path / "test.wav")
    report = Steganalyzer.analyze_carrier(wav_path)

    assert isinstance(report, SteganalysisReport)
    assert "Audio" in report.media_type
    assert report.chi2_dof > 0
    assert 0.0 <= report.chi2_p_value <= 1.0


def test_dump_lsb_map(tmp_path: Path):
    img_path = create_test_image(tmp_path / "carrier.png")
    out_map = tmp_path / "lsb_map.png"

    result = Steganalyzer.dump_lsb_map(img_path, out_map)
    assert result == out_map
    assert out_map.exists()

    with Image.open(out_map) as im:
        assert im.size == (120, 120)


def test_analyze_missing_file():
    with pytest.raises(FileNotFoundError):
        Steganalyzer.analyze_carrier(Path("non_existent_file.png"))


def test_analyze_unsupported_format(tmp_path: Path):
    txt_file = tmp_path / "document.txt"
    txt_file.write_text("Hello")
    with pytest.raises(ValueError, match="Unsupported carrier for steganalysis"):
        Steganalyzer.analyze_carrier(txt_file)
