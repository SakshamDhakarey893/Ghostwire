"""
GhostWire input validation.

This module validates user-controlled paths and basic
conditions before GhostWire performs cryptographic or
steganographic operations.
"""

from __future__ import annotations

from pathlib import Path


class ValidationError(Exception):
    """Raised when GhostWire input fails validation."""


def validate_payload(payload_path: Path) -> None:
    """
    Validate the payload file.
    """

    if not payload_path.exists():
        raise ValidationError(
            f"Payload does not exist: {payload_path}"
        )

    if not payload_path.is_file():
        raise ValidationError(
            f"Payload is not a file: {payload_path}"
        )

    if payload_path.stat().st_size == 0:
        raise ValidationError(
            "Payload file is empty."
        )


def validate_carrier(carrier_path: Path) -> None:
    """
    Validate the carrier image.
    """

    if not carrier_path.exists():
        raise ValidationError(
            f"Carrier image does not exist: {carrier_path}"
        )

    if not carrier_path.is_file():
        raise ValidationError(
            f"Carrier path is not a file: {carrier_path}"
        )

    if carrier_path.suffix.lower() != ".png":
        raise ValidationError(
            "Carrier image must be a PNG file."
        )


def validate_output_path(
    output_path: Path,
    carrier_path: Path,
) -> None:
    """
    Validate the output image path.
    """

    if output_path.suffix.lower() != ".png":
        raise ValidationError(
            "Output image must use the .png extension."
        )

    if output_path.resolve() == carrier_path.resolve():
        raise ValidationError(
            "Output image cannot be the same as the carrier image."
        )

    if output_path.exists():
        raise ValidationError(
            f"Output file already exists: {output_path}"
        )


def validate_output_directory(
    output_directory: Path,
) -> None:
    """
    Validate/create the extraction output directory.
    """

    if output_directory.exists():
        if not output_directory.is_dir():
            raise ValidationError(
                f"Output path is not a directory: "
                f"{output_directory}"
            )
        return

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )


def validate_password(password: str) -> None:
    """
    Validate a GhostWire password.
    """

    if not password:
        raise ValidationError(
            "Password cannot be empty."
        )

    if not password.strip():
        raise ValidationError(
            "Password cannot contain only whitespace."
        )