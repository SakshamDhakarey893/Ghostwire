"""
GhostWire metadata packet.

Defines the header stored before the encrypted payload.
"""

from dataclasses import dataclass
import struct


MAGIC = b"GW"
VERSION = 1
HASH_SIZE = 32

# Fixed-size header:
# magic       2 bytes
# version     1 byte
# flags       1 byte
# filename_len 2 bytes
# payload_len 8 bytes
# sha256      32 bytes
HEADER_FORMAT = ">2sBBHQ32s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


@dataclass(frozen=True)
class MetadataPacket:
    """Metadata required to reconstruct a GhostWire payload."""

    filename: str
    payload_size: int
    payload_hash: bytes
    flags: int = 0
    version: int = VERSION

    def serialize(self) -> bytes:
        """Convert metadata into a fixed binary header."""

        filename_bytes = self.filename.encode("utf-8")

        if len(filename_bytes) > 65535:
            raise ValueError("Filename is too long.")

        if self.payload_size < 0:
            raise ValueError("Payload size cannot be negative.")

        if len(self.payload_hash) != HASH_SIZE:
            raise ValueError("SHA-256 hash must be exactly 32 bytes.")

        return struct.pack(
            HEADER_FORMAT,
            MAGIC,
            self.version,
            self.flags,
            len(filename_bytes),
            self.payload_size,
            self.payload_hash,
        ) + filename_bytes

    @classmethod
    def deserialize(cls, data: bytes) -> "MetadataPacket":
        """Reconstruct metadata from serialized bytes."""

        if len(data) < HEADER_SIZE:
            raise ValueError("Metadata is too short.")

        (
            magic,
            version,
            flags,
            filename_length,
            payload_size,
            payload_hash,
        ) = struct.unpack(
            HEADER_FORMAT,
            data[:HEADER_SIZE],
        )

        if magic != MAGIC:
            raise ValueError("Invalid GhostWire header.")

        end = HEADER_SIZE + filename_length

        if len(data) < end:
            raise ValueError("Incomplete filename data.")

        filename = data[HEADER_SIZE:end].decode("utf-8")

        return cls(
            filename=filename,
            payload_size=payload_size,
            payload_hash=payload_hash,
            flags=flags,
            version=version,
        )