"""
GhostWire payload processing pipeline.

Handles:
    file -> hash -> compress -> encrypt -> metadata -> packet

and:

    packet -> metadata -> decrypt -> decompress -> hash verification
"""

from dataclasses import dataclass
from pathlib import Path

from core.compression import CompressionManager
from core.crypto import CryptoManager
from core.integrity import IntegrityManager
from core.metadata import MetadataPacket
from core.packet import PacketHeader


@dataclass(frozen=True)
class PreparedPayload:
    """Payload ready to be embedded into a carrier."""

    packet: bytes
    filename: str


@dataclass(frozen=True)
class RecoveredPayload:
    """Payload recovered from a GhostWire packet."""

    filename: str
    data: bytes


class PayloadProcessor:
    """Prepare and recover GhostWire payloads."""

    def __init__(self, password: str):
        self.crypto = CryptoManager(password)

    def prepare(
        self,
        payload_path: str | Path,
    ) -> PreparedPayload:
        """
        Prepare a file for steganographic embedding.

        Pipeline:

            file
            -> SHA-256
            -> compression
            -> AES-GCM
            -> metadata
            -> packet header
            -> packet
        """

        path = Path(payload_path)

        if not path.is_file():
            raise FileNotFoundError(
                f"Payload file not found: {path}"
            )

        original_data = path.read_bytes()

        payload_hash = IntegrityManager.calculate_hash(
            original_data
        )

        compressed_data = CompressionManager.compress(
            original_data
        )

        encrypted_data = self.crypto.encrypt(
            compressed_data
        )

        metadata = MetadataPacket(
            filename=path.name,
            payload_size=len(original_data),
            payload_hash=payload_hash,
        )

        metadata_bytes = metadata.serialize()

        # Packet body:
        #
        # [4-byte metadata length]
        # [metadata]
        # [encrypted payload]

        metadata_length = len(metadata_bytes)

        body = (
            metadata_length.to_bytes(4, "big")
            + metadata_bytes
            + encrypted_data
        )

        header = PacketHeader(
            packet_size=len(body)
        )

        packet = (
            header.serialize()
            + body
        )

        return PreparedPayload(
            packet=packet,
            filename=path.name,
        )

    def recover(
        self,
        packet: bytes,
    ) -> RecoveredPayload:
        """
        Recover the original file from a GhostWire packet.

        Pipeline:

            packet
            -> header
            -> metadata
            -> AES-GCM
            -> decompression
            -> SHA-256 verification
        """

        header = PacketHeader.deserialize(packet)

        packet_start = header.header_size
        packet_end = packet_start + header.packet_size

        if len(packet) < packet_end:
            raise ValueError(
                "Incomplete GhostWire packet."
            )

        body = packet[
            packet_start:packet_end
        ]

        if len(body) < 4:
            raise ValueError(
                "Packet body is incomplete."
            )

        metadata_length = int.from_bytes(
            body[:4],
            "big",
        )

        metadata_start = 4
        metadata_end = metadata_start + metadata_length

        if metadata_end > len(body):
            raise ValueError(
                "Invalid metadata length."
            )

        metadata_bytes = body[
            metadata_start:metadata_end
        ]

        encrypted_data = body[
            metadata_end:
        ]

        metadata = MetadataPacket.deserialize(
            metadata_bytes
        )

        compressed_data = self.crypto.decrypt(
            encrypted_data
        )

        original_data = CompressionManager.decompress(
            compressed_data
        )

        if len(original_data) != metadata.payload_size:
            raise ValueError(
                "Recovered payload size does not match metadata."
            )

        if not IntegrityManager.verify_hash(
            original_data,
            metadata.payload_hash,
        ):
            raise ValueError(
                "Payload integrity verification failed."
            )

        return RecoveredPayload(
            filename=metadata.filename,
            data=original_data,
        )