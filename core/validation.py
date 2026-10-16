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


SUPPORTED_CARRIER_EXTENSIONS = {".png", ".wav"}


def validate_carrier(carrier_path: Path) -> None:
    """
    Validate the carrier media file (PNG image or WAV audio).
    """

    if not carrier_path.exists():
        raise ValidationError(
            f"Carrier file does not exist: {carrier_path}"
        )

    if not carrier_path.is_file():
        raise ValidationError(
            f"Carrier path is not a file: {carrier_path}"
        )

    ext = carrier_path.suffix.lower()
    if ext not in SUPPORTED_CARRIER_EXTENSIONS:
        raise ValidationError(
            f"Unsupported carrier format: {carrier_path.suffix}. "
            "Carrier must be a PNG image or WAV audio file."
        )


def validate_output_path(
    output_path: Path,
    carrier_path: Path,
    force: bool = False,
) -> None:
    """
    Validate the output carrier path.
    """

    carrier_ext = carrier_path.suffix.lower()
    output_ext = output_path.suffix.lower()

    if output_ext not in SUPPORTED_CARRIER_EXTENSIONS:
        raise ValidationError(
            f"Unsupported output format: {output_path.suffix}. "
            "Output must be a PNG image or WAV audio file."
        )

    if output_ext != carrier_ext:
        raise ValidationError(
            f"Output file extension ({output_ext}) must match carrier extension ({carrier_ext})."
        )

    if output_path.resolve() == carrier_path.resolve():
        raise ValidationError(
            "Output file cannot be the same as the carrier file."
        )

    if output_path.exists() and not force:
        raise ValidationError(
            f"Output file already exists: {output_path}. Use --force to overwrite."
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