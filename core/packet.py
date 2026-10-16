"""
GhostWire packet framing.

Defines the fixed bootstrap header used to determine the
size of the remaining GhostWire packet.
"""

from dataclasses import dataclass
import struct


MAGIC = b"GW"
VERSION = 1

HEADER_FORMAT = ">2sBBI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Safety limit for the first implementation.
# This prevents unreasonable extraction requests.
MAX_PACKET_SIZE = 100 * 1024 * 1024  # 100 MB


@dataclass(frozen=True)
class PacketHeader:
    """Fixed GhostWire bootstrap header."""

    packet_size: int
    flags: int = 0
    version: int = VERSION

    def serialize(self) -> bytes:
        """Serialize the bootstrap header."""

        if self.packet_size < 0:
            raise ValueError(
                "Packet size cannot be negative."
            )

        if self.packet_size > MAX_PACKET_SIZE:
            raise ValueError(
                "Packet exceeds maximum supported size."
            )

        return struct.pack(
            HEADER_FORMAT,
            MAGIC,
            self.version,
            self.flags,
            self.packet_size,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "PacketHeader":
        """Deserialize and validate a bootstrap header."""

        if len(data) < HEADER_SIZE:
            raise ValueError(
                "Incomplete GhostWire packet header."
            )

        (
            magic,
            version,
            flags,
            packet_size,
        ) = struct.unpack(
            HEADER_FORMAT,
            data[:HEADER_SIZE],
        )

        if magic != MAGIC:
            raise ValueError(
                "Invalid GhostWire magic header."
            )

        if version != VERSION:
            raise ValueError(
                f"Unsupported GhostWire version: {version}"
            )

        if packet_size > MAX_PACKET_SIZE:
            raise ValueError(
                "Packet exceeds maximum supported size."
            )

        return cls(
            packet_size=packet_size,
            flags=flags,
            version=version,
        )