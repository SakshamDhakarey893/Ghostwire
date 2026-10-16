"""
GhostWire
---------
Randomized LSB steganography command-line tool.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from core.stego_service import StegoService
from core.validation import ValidationError


def get_password(
    provided_password: str | None,
    confirm: bool = False,
) -> str:
    """
    Get a password from the command line or securely prompt for it.
    """

    if provided_password is not None:
        if not provided_password:
            raise ValueError("Password cannot be empty.")

        return provided_password

    password = getpass.getpass("Password: ")

    if not password:
        raise ValueError("Password cannot be empty.")

    if confirm:
        confirmation = getpass.getpass("Confirm password: ")

        if password != confirmation:
            raise ValueError("Passwords do not match.")

    return password


def build_parser() -> argparse.ArgumentParser:
    """
    Build the GhostWire CLI parser.
    """

    parser = argparse.ArgumentParser(
        prog="ghostwire",
        description="GhostWire - randomized LSB steganography tool",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ================================================================
    # EMBED
    # ================================================================

    embed_parser = subparsers.add_parser(
        "embed",
        help="Hide a payload inside a digital carrier (PNG or WAV).",
        description=(
            "Encrypt and hide a payload inside a PNG image or WAV audio file "
            "using randomized LSB steganography."
        ),
    )

    embed_parser.add_argument(
        "-p",
        "--payload",
        required=True,
        type=Path,
        help="Path to the payload file.",
    )

    embed_parser.add_argument(
        "-c",
        "--carrier",
        required=True,
        type=Path,
        help="Path to the carrier media (PNG or WAV).",
    )

    embed_parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=Path,
        help="Path for the output stego media (PNG or WAV).",
    )

    embed_parser.add_argument(
        "--password",
        default=None,
        help=(
            "Encryption password. "
            "If omitted, GhostWire prompts securely."
        ),
    )

    # ================================================================
    # EXTRACT
    # ================================================================

    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract a hidden payload from a digital carrier (PNG or WAV).",
        description=(
            "Extract and decrypt a payload from a "
            "GhostWire PNG or WAV carrier."
        ),
    )

    extract_parser.add_argument(
        "-c",
        "--carrier",
        required=True,
        type=Path,
        help="Path to the GhostWire carrier (PNG or WAV).",
    )

    extract_parser.add_argument(
        "-o",
        "--output-dir",
        required=True,
        type=Path,
        help="Directory for the recovered payload.",
    )

    extract_parser.add_argument(
        "--password",
        default=None,
        help=(
            "Decryption password. "
            "If omitted, GhostWire prompts securely."
        ),
    )

    return parser


def run_embed(args: argparse.Namespace) -> int:
    """
    Run the embed operation.
    """

    password = get_password(
        args.password,
        confirm=True,
    )

    service = StegoService()

    service.embed(
        payload_path=args.payload,
        carrier_path=args.carrier,
        output_path=args.output,
        password=password,
    )

    print(
        f"[+] Payload successfully embedded: "
        f"{args.output}"
    )

    return 0


def run_extract(args: argparse.Namespace) -> int:
    """
    Run the extraction operation.
    """

    password = get_password(
        args.password,
        confirm=False,
    )

    service = StegoService()

    output_path = service.extract(
        carrier_path=args.carrier,
        output_directory=args.output_dir,
        password=password,
    )

    print(
        f"[+] Payload successfully extracted: "
        f"{output_path}"
    )

    return 0


def main() -> int:
    """
    Main GhostWire entry point.
    """

    parser = build_parser()

    try:
        args = parser.parse_args()

        if args.command == "embed":
            return run_embed(args)

        if args.command == "extract":
            return run_extract(args)

        parser.error("A valid command is required.")

    except KeyboardInterrupt:
        print(
            "\n[!] Operation cancelled.",
            file=sys.stderr,
        )
        return 130

    except ValidationError as exc:
        print(
            f"[!] Validation error: {exc}",
            file=sys.stderr,
        )
        return 1

    except ValueError as exc:
        print(
            f"[!] Error: {exc}",
            file=sys.stderr,
        )
        return 1

    except FileNotFoundError as exc:
        print(
            f"[!] File not found: {exc}",
            file=sys.stderr,
        )
        return 1

    except Exception as exc:
        print(
            f"[!] GhostWire error: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())