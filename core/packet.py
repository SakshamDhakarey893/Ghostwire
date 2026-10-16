"""
GhostWire packet framing.

Defines the fixed bootstrap header used to determine the
protocol version, random position salt, and payload packet size.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import struct


MAGIC = b"GW"
VERSION = 2

SALT_SIZE = 16

# Version 1 header: 8 bytes (legacy)
HEADER_FORMAT_V1 = ">2sBBI"
HEADER_SIZE_V1 = struct.calcsize(HEADER_FORMAT_V1)

# Version 2 header: 24 bytes (includes 16-byte random salt for position randomization)
HEADER_FORMAT_V2 = ">2sBBI16s"
HEADER_SIZE_V2 = struct.calcsize(HEADER_FORMAT_V2)

# Default header size for current protocol version
HEADER_SIZE = HEADER_SIZE_V2

# Safety limit to prevent unreasonable extraction allocations (100 MB).
MAX_PACKET_SIZE = 100 * 1024 * 1024


@dataclass(frozen=True)
class PacketHeader:
    """Fixed GhostWire bootstrap header."""

    packet_size: int
    flags: int = 0
    version: int = VERSION
    salt: bytes = field(default_factory=lambda: os.urandom(SALT_SIZE))

    @property
    def header_size(self) -> int:
        """Return the size in bytes of this header version."""
        return HEADER_SIZE_V1 if self.version == 1 else HEADER_SIZE_V2

    def serialize(self) -> bytes:
        """Serialize the bootstrap header."""
        if self.packet_size < 0:
            raise ValueError("Packet size cannot be negative.")

        if self.packet_size > MAX_PACKET_SIZE:
            raise ValueError("Packet exceeds maximum supported size.")

        if self.version == 1:
            return struct.pack(
                HEADER_FORMAT_V1,
                MAGIC,
                1,
                self.flags,
                self.packet_size,
            )

        if self.version == 2:
            salt = self.salt
            if len(salt) != SALT_SIZE:
                raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes.")

            return struct.pack(
                HEADER_FORMAT_V2,
                MAGIC,
                2,
                self.flags,
                self.packet_size,
                salt,
            )

        raise ValueError(f"Unsupported GhostWire version: {self.version}")

    @classmethod
    def deserialize(cls, data: bytes) -> "PacketHeader":
        """Deserialize and validate a bootstrap header."""
        if len(data) < HEADER_SIZE_V1:
            raise ValueError("Incomplete GhostWire packet header.")

        magic = data[:2]
        if magic != MAGIC:
            raise ValueError("Invalid GhostWire magic header.")

        version = data[2]
        if version == 1:
            (
                magic,
                ver,
                flags,
                packet_size,
            ) = struct.unpack(
                HEADER_FORMAT_V1,
                data[:HEADER_SIZE_V1],
            )
            if packet_size > MAX_PACKET_SIZE:
                raise ValueError("Packet exceeds maximum supported size.")

            return cls(
                packet_size=packet_size,
                flags=flags,
                version=1,
                salt=b"",
            )

        if version == 2:
            if len(data) < HEADER_SIZE_V2:
                raise ValueError("Incomplete GhostWire v2 packet header.")

            (
                magic,
                ver,
                flags,
                packet_size,
                salt,
            ) = struct.unpack(
                HEADER_FORMAT_V2,
                data[:HEADER_SIZE_V2],
            )
            if packet_size > MAX_PACKET_SIZE:
                raise ValueError("Packet exceeds maximum supported size.")

            return cls(
                packet_size=packet_size,
                flags=flags,
                version=2,
                salt=salt,
            )

        raise ValueError(f"Unsupported GhostWire version: {version}")