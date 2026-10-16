"""
GhostWire cryptographic utilities.

Provides password-based key derivation and authenticated
encryption/decryption using AES-256-GCM.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    """Handle password-based AES-256-GCM encryption."""

    SALT_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32

    # PBKDF2 work factor.
    PBKDF2_ITERATIONS = 600_000

    def __init__(self, password: str):
        if not password:
            raise ValueError("Password cannot be empty.")

        self.password = password

    def derive_key(self, salt: bytes) -> bytes:
        """
        Derive a 256-bit encryption key from the password.

        Args:
            salt: Random salt used for key derivation.

        Returns:
            32-byte AES-256 key.
        """

        if len(salt) != self.SALT_SIZE:
            raise ValueError(
                f"Salt must be {self.SALT_SIZE} bytes."
            )

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )

        return kdf.derive(
            self.password.encode("utf-8")
        )

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Encrypt plaintext using AES-256-GCM.

        The returned value contains:

            salt + nonce + ciphertext

        AES-GCM authentication data is included in the ciphertext
        returned by the cryptography library.

        Args:
            plaintext: Data to encrypt.
            associated_data: Optional authenticated-but-unencrypted data.

        Returns:
            Binary encryption envelope.
        """

        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)

        key = self.derive_key(salt)

        aes = AESGCM(key)

        ciphertext = aes.encrypt(
            nonce,
            plaintext,
            associated_data,
        )

        return salt + nonce + ciphertext

    def decrypt(
        self,
        encrypted_data: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Decrypt and authenticate an AES-256-GCM envelope.

        Args:
            encrypted_data: salt + nonce + ciphertext.
            associated_data: Optional authenticated data.

        Returns:
            Original plaintext.

        Raises:
            ValueError: If the encrypted data is malformed.
            cryptography.exceptions.InvalidTag:
                If authentication fails.
        """

        minimum_size = (
            self.SALT_SIZE
            + self.NONCE_SIZE
            + 16  # AES-GCM authentication tag
        )

        if len(encrypted_data) < minimum_size:
            raise ValueError("Encrypted data is too short.")

        salt = encrypted_data[
            :self.SALT_SIZE
        ]

        nonce_start = self.SALT_SIZE
        nonce_end = nonce_start + self.NONCE_SIZE

        nonce = encrypted_data[
            nonce_start:nonce_end
        ]

        ciphertext = encrypted_data[nonce_end:]

        key = self.derive_key(salt)

        aes = AESGCM(key)

        return aes.decrypt(
            nonce,
            ciphertext,
            associated_data,
        )