"""
Integration and unit tests for Multi-Carrier Steganography Engine.
"""

from pathlib import Path
from PIL import Image
import pytest
import wave
import struct

from core.multi_carrier import MultiCarrierService, MAGIC_MC


def create_image_carrier(path: Path, width: int = 150, height: int = 150) -> Path:
    img = Image.new("RGB", (width, height), (100, 150, 200))
    img.save(path, format="PNG")
    return path


def create_audio_carrier(path: Path, n_frames: int = 10000) -> Path:
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(struct.pack(f"<{n_frames*2}h", *range(n_frames * 2)))
    return path


def test_chunk_pack_and_unpack():
    bundle_id = b"0123456789abcdef"
    file_hash = b"X" * 32
    data = b"MultiCarrierChunkTestData"

    packed = MultiCarrierService.pack_chunk(
        bundle_id=bundle_id,
        part_index=1,
        total_parts=4,
        filename="test.bin",
        file_hash=file_hash,
        chunk_data=data,
    )

    unpacked = MultiCarrierService.unpack_chunk(packed)
    assert unpacked is not None
    assert unpacked.bundle_id == bundle_id
    assert unpacked.part_index == 1
    assert unpacked.total_parts == 4
    assert unpacked.filename == "test.bin"
    assert unpacked.file_hash == file_hash
    assert unpacked.chunk_data == data


def test_multi_carrier_split_and_reassemble_mixed(tmp_path: Path):
    """
    Split a payload across heterogeneous carriers: 2 PNG images + 1 WAV audio.
    Verify successful reconstruction and byte-for-byte fidelity.
    """
    payload_file = tmp_path / "important_contract.pdf"
    original_data = (
        b"%PDF-1.7 Confidential Multi-Carrier Split Payload Contract.\n"
        b"This payload is partitioned across mixed image and audio carriers.\n" * 20
    )
    payload_file.write_bytes(original_data)

    c1 = create_image_carrier(tmp_path / "c1.png", 150, 150)
    c2 = create_audio_carrier(tmp_path / "c2.wav", 8000)
    c3 = create_image_carrier(tmp_path / "c3.png", 150, 150)

    o1 = tmp_path / "stego1.png"
    o2 = tmp_path / "stego2.wav"
    o3 = tmp_path / "stego3.png"

    mc = MultiCarrierService()
    written = mc.split_and_embed(
        payload_path=payload_file,
        carrier_paths=[c1, c2, c3],
        output_paths=[o1, o2, o3],
        password="MultiCarrierPassword999",
        force=True,
    )

    assert len(written) == 3
    for out in [o1, o2, o3]:
        assert out.exists()
        assert out.stat().st_size > 0

    # Reconstruct from carriers in non-sequential order (o3, o1, o2)
    recovered_path = mc.reconstruct_and_extract(
        carrier_paths=[o3, o1, o2],
        output_target=tmp_path / "recovered_dir",
        password="MultiCarrierPassword999",
        force=True,
    )

    assert recovered_path.exists()
    assert recovered_path.name == "important_contract.pdf"
    assert recovered_path.read_bytes() == original_data


def test_multi_carrier_single_carrier_informative_error(tmp_path: Path):
    """
    Attempting to extract a multi-carrier segment individually must raise an
    informative error notifying the user which bundle part was provided.
    """
    payload_file = tmp_path / "msg.txt"
    payload_file.write_bytes(b"Short payload across two carriers.")

    c1 = create_image_carrier(tmp_path / "c1.png", 100, 100)
    c2 = create_image_carrier(tmp_path / "c2.png", 100, 100)
    o1 = tmp_path / "stego1.png"
    o2 = tmp_path / "stego2.png"

    mc = MultiCarrierService()
    mc.split_and_embed(
        payload_path=payload_file,
        carrier_paths=[c1, c2],
        output_paths=[o1, o2],
        password="secretpassword",
    )

    # Passing only 1 carrier
    with pytest.raises(ValueError, match="Multi-Carrier Bundle detected: Part 1 of 2"):
        mc.reconstruct_and_extract(
            carrier_paths=[o1],
            output_target=tmp_path / "out",
            password="secretpassword",
        )


def test_multi_carrier_missing_part_fails(tmp_path: Path):
    """Passing duplicate parts or incomplete bundle fails reassembly."""
    payload_file = tmp_path / "data.bin"
    payload_file.write_bytes(b"Binary Data" * 50)

    c1 = create_image_carrier(tmp_path / "c1.png", 100, 100)
    c2 = create_image_carrier(tmp_path / "c2.png", 100, 100)
    o1 = tmp_path / "s1.png"
    o2 = tmp_path / "s2.png"

    mc = MultiCarrierService()
    mc.split_and_embed(
        payload_path=payload_file,
        carrier_paths=[c1, c2],
        output_paths=[o1, o2],
        password="password",
    )

    # Passing duplicate part 1 instead of parts 1 and 2
    with pytest.raises(ValueError, match="Duplicate carrier parts detected"):
        mc.reconstruct_and_extract(
            carrier_paths=[o1, o1],
            output_target=tmp_path / "out",
            password="password",
        )
