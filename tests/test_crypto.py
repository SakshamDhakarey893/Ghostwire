import pytest

from cryptography.exceptions import InvalidTag

from core.crypto import CryptoManager


def test_encrypt_decrypt_round_trip():
    password = "ghostwire-test-password"
    plaintext = b"GhostWire secret payload"

    crypto = CryptoManager(password)

    encrypted = crypto.encrypt(plaintext)
    decrypted = crypto.decrypt(encrypted)

    assert decrypted == plaintext


def test_encryption_is_randomized():
    password = "ghostwire-test-password"
    plaintext = b"same plaintext"

    crypto = CryptoManager(password)

    encrypted1 = crypto.encrypt(plaintext)
    encrypted2 = crypto.encrypt(plaintext)

    assert encrypted1 != encrypted2


def test_wrong_password_fails():
    plaintext = b"secret payload"

    encryptor = CryptoManager("correct-password")
    encrypted = encryptor.encrypt(plaintext)

    decryptor = CryptoManager("wrong-password")

    with pytest.raises(InvalidTag):
        decryptor.decrypt(encrypted)


def test_modified_ciphertext_fails():
    plaintext = b"secret payload"

    crypto = CryptoManager("correct-password")
    encrypted = bytearray(crypto.encrypt(plaintext))

    # Modify the final byte of the authenticated ciphertext.
    encrypted[-1] ^= 1

    with pytest.raises(InvalidTag):
        crypto.decrypt(bytes(encrypted))


def test_associated_data_is_authenticated():
    plaintext = b"secret payload"

    crypto = CryptoManager("correct-password")

    encrypted = crypto.encrypt(
        plaintext,
        associated_data=b"GhostWire-v1",
    )

    decrypted = crypto.decrypt(
        encrypted,
        associated_data=b"GhostWire-v1",
    )

    assert decrypted == plaintext

    with pytest.raises(InvalidTag):
        crypto.decrypt(
            encrypted,
            associated_data=b"GhostWire-v2",
        )