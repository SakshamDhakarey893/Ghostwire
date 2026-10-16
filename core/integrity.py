"""
GhostWire integrity utilities.

Provides SHA-256 hashing and verification for payload data.
"""

import hashlib
import hmac


class IntegrityManager:
    """Calculate and verify SHA-256 fingerprints."""

    @staticmethod
    def calculate_hash(data: bytes) -> bytes:
        """
        Calculate the SHA-256 digest of data.

        Args:
            data: Bytes to hash.

        Returns:
            32-byte SHA-256 digest.
        """
        return hashlib.sha256(data).digest()

    @staticmethod
    def verify_hash(data: bytes, expected_hash: bytes) -> bool:
        """
        Verify data against an expected SHA-256 digest.

        Args:
            data: Data to verify.
            expected_hash: Expected 32-byte digest.

        Returns:
            True if the hashes match, otherwise False.
        """
        if len(expected_hash) != hashlib.sha256().digest_size:
            raise ValueError("Expected hash must be 32 bytes.")

        actual_hash = IntegrityManager.calculate_hash(data)

        return hmac.compare_digest(actual_hash, expected_hash)