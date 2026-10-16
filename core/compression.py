"""
GhostWire compression utilities.

Compresses payload data before encryption and decompresses it
after successful decryption.
"""

import zlib


class CompressionManager:
    """Handle payload compression and decompression."""

    DEFAULT_LEVEL = 9

    @staticmethod
    def compress(
        data: bytes,
        level: int = DEFAULT_LEVEL,
    ) -> bytes:
        """
        Compress payload data using zlib.

        Args:
            data: Bytes to compress.
            level: Compression level from 0 to 9.

        Returns:
            Compressed bytes.

        Raises:
            ValueError: If the compression level is invalid.
        """

        if not 0 <= level <= 9:
            raise ValueError(
                "Compression level must be between 0 and 9."
            )

        return zlib.compress(data, level)

    @staticmethod
    def decompress(data: bytes) -> bytes:
        """
        Decompress zlib-compressed data.

        Args:
            data: Compressed bytes.

        Returns:
            Original uncompressed bytes.

        Raises:
            ValueError: If the data is not valid zlib data.
        """

        try:
            return zlib.decompress(data)
        except zlib.error as exc:
            raise ValueError(
                "Invalid compressed payload."
            ) from exc