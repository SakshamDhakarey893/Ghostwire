"""
GhostWire Multi-Carrier Steganography Engine
--------------------------------------------
Enables splitting large encrypted payloads across multiple digital carriers
(images and audio tracks) proportionally to each carrier's capacity.

Guarantees:
- Strict bundle identification (16-byte random bundle ID)
- Sequence index verification (zero missing parts, zero duplicates)
- Global SHA-256 integrity verification across the reassembled payload
- Heterogeneous carrier mixing (e.g. 1 PNG image + 2 WAV audio tracks)
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import struct
from typing import Sequence

from core.integrity import IntegrityManager
from core.stego_service import StegoService, get_carrier_engine
from core.validation import validate_carrier, validate_password, validate_payload


MAGIC_MC = b"GWMC"
# Header format:
# magic: 4s (b"GWMC")
# bundle_id: 16s
# part_index: H (uint16)
# total_parts: H (uint16)
# filename_len: H (uint16)
# file_hash: 32s (SHA-256 digest)
# chunk_len: I (uint32)
MC_HEADER_FMT = ">4s16sHHH32sI"
MC_HEADER_SIZE = struct.calcsize(MC_HEADER_FMT)  # 62 bytes


@dataclass(frozen=True)
class MultiCarrierChunk:
    """Parsed multi-carrier envelope part."""

    bundle_id: bytes
    part_index: int
    total_parts: int
    filename: str
    file_hash: bytes
    chunk_data: bytes


class MultiCarrierService:
    """Coordinates multi-carrier splitting, embedding, and reassembly."""

    def __init__(self, stego_service: StegoService | None = None):
        self.stego_service = stego_service or StegoService()

    @staticmethod
    def pack_chunk(
        bundle_id: bytes,
        part_index: int,
        total_parts: int,
        filename: str,
        file_hash: bytes,
        chunk_data: bytes,
    ) -> bytes:
        """Serialize a payload fragment with its multi-carrier envelope."""
        fn_bytes = filename.encode("utf-8")
        if len(fn_bytes) > 65535:
            raise ValueError("Filename is too long.")
        if len(file_hash) != 32:
            raise ValueError("SHA-256 hash must be 32 bytes.")

        header = struct.pack(
            MC_HEADER_FMT,
            MAGIC_MC,
            bundle_id,
            part_index,
            total_parts,
            len(fn_bytes),
            file_hash,
            len(chunk_data),
        )
        return header + fn_bytes + chunk_data

    @staticmethod
    def unpack_chunk(data: bytes) -> MultiCarrierChunk | None:
        """
        Attempt to parse a multi-carrier chunk envelope.
        Returns None if data is not a multi-carrier segment.
        """
        if len(data) < MC_HEADER_SIZE or data[:4] != MAGIC_MC:
            return None

        (
            magic,
            bundle_id,
            part_index,
            total_parts,
            fn_len,
            file_hash,
            chunk_len,
        ) = struct.unpack(MC_HEADER_FMT, data[:MC_HEADER_SIZE])

        fn_end = MC_HEADER_SIZE + fn_len
        chunk_end = fn_end + chunk_len

        if len(data) < chunk_end:
            raise ValueError("Incomplete multi-carrier chunk envelope.")

        filename = data[MC_HEADER_SIZE:fn_end].decode("utf-8")
        chunk_data = data[fn_end:chunk_end]

        return MultiCarrierChunk(
            bundle_id=bundle_id,
            part_index=part_index,
            total_parts=total_parts,
            filename=filename,
            file_hash=file_hash,
            chunk_data=chunk_data,
        )

    def split_and_embed(
        self,
        payload_path: str | Path,
        carrier_paths: Sequence[str | Path],
        output_paths: Sequence[str | Path],
        password: str,
        force: bool = False,
        verbose: bool = False,
        show_progress: bool = True,
    ) -> list[Path]:
        """
        Split a payload proportionally across multiple carriers and embed.

        Args:
            payload_path: Path to the large secret file.
            carrier_paths: List of carrier paths (PNG or WAV).
            output_paths: List of output paths matching each carrier.
            password: Encryption password.
            force: Allow overwriting existing output files.
            verbose: Print diagnostic details.
            show_progress: Display progress bars.

        Returns:
            List of generated output stego file paths.
        """
        payload_path = Path(payload_path)
        c_paths = [Path(c) for c in carrier_paths]
        o_paths = [Path(o) for o in output_paths]

        if len(c_paths) < 2:
            raise ValueError(
                "Multi-carrier embedding requires at least 2 carriers. "
                "For single carriers, use standard embed."
            )

        if len(c_paths) != len(o_paths):
            raise ValueError(
                f"Mismatch: received {len(c_paths)} carriers but {len(o_paths)} output paths."
            )

        validate_payload(payload_path)
        validate_password(password)
        for c in c_paths:
            validate_carrier(c)

        # 1. Read payload and calculate global integrity hash
        payload_bytes = payload_path.read_bytes()
        file_hash = IntegrityManager.calculate_hash(payload_bytes)
        total_payload_len = len(payload_bytes)
        bundle_id = os.urandom(16)

        # 2. Query available capacities
        capacities: list[int] = []
        for c in c_paths:
            stego = get_carrier_engine(c)
            # Available bits converted to usable safe bytes
            cap_bits = stego.calculate_capacity(c)
            capacities.append(cap_bits // 8)

        total_capacity_bytes = sum(capacities)
        est_total_overhead = len(c_paths) * (MC_HEADER_SIZE + len(payload_path.name.encode()) + 250)

        if (total_payload_len + est_total_overhead) > total_capacity_bytes:
            raise ValueError(
                f"Combined carrier capacity ({total_capacity_bytes:,} bytes) is insufficient "
                f"for payload ({total_payload_len:,} bytes) plus protocol overhead."
            )

        # 3. Partition payload proportionally to carrier capacities
        chunks: list[bytes] = []
        offset = 0
        for i, cap in enumerate(capacities):
            if i == len(capacities) - 1:
                # Last carrier gets remaining bytes
                chunk = payload_bytes[offset:]
            else:
                portion = int(round(total_payload_len * (cap / total_capacity_bytes)))
                # Ensure each carrier gets at least 1 byte if data remains
                portion = max(1, min(portion, total_payload_len - offset))
                chunk = payload_bytes[offset : offset + portion]
                offset += portion
            chunks.append(chunk)

        if verbose:
            print(f"[*] Multi-Carrier Bundle ID: {bundle_id.hex()[:16]}...")
            print(f"[*] Total Payload Size: {total_payload_len:,} bytes across {len(c_paths)} carriers")
            for i, (c, o, ch, cap) in enumerate(zip(c_paths, o_paths, chunks, capacities)):
                print(f"    - Part {i+1}: {len(ch):,} bytes -> {c.name} (Cap: {cap:,} bytes) -> {o.name}")

        # 4. Embed each chunk envelope into its designated carrier
        written_outputs: list[Path] = []
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            for i, (carrier, output_file, chunk_data) in enumerate(zip(c_paths, o_paths, chunks)):
                envelope = self.pack_chunk(
                    bundle_id=bundle_id,
                    part_index=i,
                    total_parts=len(c_paths),
                    filename=payload_path.name,
                    file_hash=file_hash,
                    chunk_data=chunk_data,
                )

                chunk_tmp = tmp_dir_path / f"chunk_{i}.bin"
                chunk_tmp.write_bytes(envelope)

                self.stego_service.embed(
                    payload_path=chunk_tmp,
                    carrier_path=carrier,
                    output_path=output_file,
                    password=password,
                    force=force,
                    show_progress=show_progress,
                    verbose=verbose,
                )
                written_outputs.append(output_file)

        return written_outputs

    def reconstruct_and_extract(
        self,
        carrier_paths: Sequence[str | Path],
        output_target: str | Path,
        password: str,
        force: bool = False,
        verbose: bool = False,
        show_progress: bool = True,
    ) -> Path:
        """
        Extract fragments from multiple carriers, verify bundle identity,
        re-sequence parts, and reconstruct the verified original payload.
        """
        c_paths = [Path(c) for c in carrier_paths]
        if not c_paths:
            raise ValueError("No carriers provided for extraction.")

        validate_password(password)
        for c in c_paths:
            if not c.is_file():
                raise FileNotFoundError(f"Carrier file not found: {c}")
            validate_carrier(c)

        import tempfile

        parsed_chunks: list[MultiCarrierChunk] = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_path = Path(tmp_dir)

            for i, carrier in enumerate(c_paths):
                part_dest = tmp_dir_path / f"part_{i}.tmp"
                self.stego_service.extract(
                    carrier_path=carrier,
                    output_directory=part_dest,
                    password=password,
                    force=True,
                    show_progress=show_progress,
                    verbose=verbose,
                )

                raw_bytes = part_dest.read_bytes()
                parsed = self.unpack_chunk(raw_bytes)

                if parsed is None:
                    # Carrier does not contain a multi-carrier envelope
                    if len(c_paths) == 1:
                        # User passed single regular carrier to multi-carrier extract
                        raise ValueError(
                            "Carrier contains a standard single-carrier payload, not a multi-carrier bundle. "
                            "Use standard 'ghostwire extract' instead."
                        )
                    raise ValueError(
                        f"Carrier '{carrier.name}' does not contain a valid GhostWire multi-carrier envelope."
                    )

                parsed_chunks.append(parsed)

        # Handle single carrier inquiry
        first_chunk = parsed_chunks[0]
        bundle_id = first_chunk.bundle_id
        expected_total = first_chunk.total_parts

        if len(c_paths) < expected_total:
            raise ValueError(
                f"Multi-Carrier Bundle detected: Part {first_chunk.part_index + 1} of {expected_total} "
                f"(Bundle ID: {bundle_id.hex()[:8]}...). "
                f"You provided {len(c_paths)} carrier(s), but all {expected_total} carriers are required."
            )

        # 1. Validate bundle ID consistency
        for chunk in parsed_chunks:
            if chunk.bundle_id != bundle_id:
                raise ValueError(
                    f"Bundle ID mismatch: carrier contains part from bundle {chunk.bundle_id.hex()[:8]}..., "
                    f"expected bundle {bundle_id.hex()[:8]}..."
                )
            if chunk.total_parts != expected_total:
                raise ValueError("Inconsistent total_parts declared across carriers.")

        # 2. Check for duplicate and missing parts
        indices = [chunk.part_index for chunk in parsed_chunks]
        if len(indices) != len(set(indices)):
            raise ValueError(f"Duplicate carrier parts detected: {indices}")

        expected_indices = set(range(expected_total))
        if set(indices) != expected_indices:
            missing = sorted(list(expected_indices - set(indices)))
            raise ValueError(f"Missing bundle parts: {missing}")

        # 3. Sort chunks by part_index (0, 1, ... N-1)
        sorted_chunks = sorted(parsed_chunks, key=lambda c: c.part_index)

        # 4. Assemble original payload stream
        assembled_data = b"".join(c.chunk_data for c in sorted_chunks)

        # 5. Verify global SHA-256 integrity
        if not IntegrityManager.verify_hash(assembled_data, first_chunk.file_hash):
            raise ValueError(
                "Multi-carrier payload integrity verification failed! "
                "One or more carrier chunks appear corrupted or tampered."
            )

        # 6. Write final reconstructed file
        out_target = Path(output_target)
        if (
            out_target.is_dir()
            or str(output_target).endswith(("/", "\\"))
            or not out_target.suffix
        ):
            out_target.mkdir(parents=True, exist_ok=True)
            destination = out_target / first_chunk.filename
        else:
            out_target.parent.mkdir(parents=True, exist_ok=True)
            destination = out_target

        if destination.exists() and not force:
            raise ValueError(
                f"Output file already exists: {destination}. Use --force to overwrite."
            )

        destination.write_bytes(assembled_data)

        if verbose:
            print(f"[+] Reassembled {len(sorted_chunks)} parts ({len(assembled_data):,} bytes)")
            print(f"[+] Verified SHA-256 Digest: {first_chunk.file_hash.hex()}")

        return destination
