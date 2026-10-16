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

VERSION = "2.0.0"


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable representation."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB"
    if num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"
    return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


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
        description="GhostWire — Professional Randomized LSB Steganography Framework",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"GhostWire v{VERSION}",
        help="Show program's version number and exit.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ================================================================
    # CAPACITY
    # ================================================================
    capacity_parser = subparsers.add_parser(
        "capacity",
        help="Inspect carrier capacity and metadata.",
        description="Calculate maximum payload capacity for PNG images and WAV audio carriers.",
    )

    capacity_parser.add_argument(
        "-c",
        "--carrier",
        required=True,
        type=Path,
        help="Path to the carrier media (PNG or WAV).",
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
        help="Encryption password. If omitted, GhostWire prompts securely.",
    )

    embed_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )

    embed_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging.",
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
        "--output",
        "--output-dir",
        dest="output",
        required=True,
        type=Path,
        help="Output directory or specific destination file for recovered payload.",
    )

    extract_parser.add_argument(
        "--password",
        default=None,
        help="Decryption password. If omitted, GhostWire prompts securely.",
    )

    extract_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite destination file if it already exists.",
    )

    extract_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging.",
    )

    return parser


def run_capacity(args: argparse.Namespace) -> int:
    """
    Run the capacity inspection command.
    """
    service = StegoService()
    info = service.get_capacity(args.carrier)

    print(f"[+] Carrier File: {args.carrier.resolve()}")
    print(f"    - Media Type: {info['type']} ({info['format']})")

    if info["type"] == "Image":
        print(f"    - Dimensions: {info['width']} x {info['height']} pixels")
        print(f"    - Color Mode: {info['mode']} (Using {info['channels']} color channels)")
    elif info["type"] == "Audio":
        print(f"    - Audio Format: {info['framerate']} Hz, {info['channels']} channel(s), {info['sample_width']}-bit PCM")
        print(f"    - Audio Length: {info['duration_seconds']}s ({info['frames']:,} frames)")

    cap_bits = int(info["capacity_bits"])
    cap_bytes = int(info["capacity_bytes"])
    print("\n[+] Steganographic Capacity (1-bit LSB):")
    print(f"    - Raw Bits:   {cap_bits:,} bits")
    print(f"    - Raw Bytes:  {cap_bytes:,} bytes")
    print(f"    - Safe Size:  ~{format_bytes(int(cap_bytes * 0.95))} (accounting for metadata & encryption overhead)")

    return 0


def run_embed(args: argparse.Namespace) -> int:
    """
    Run the embed operation.
    """
    password = get_password(args.password, confirm=True)
    service = StegoService()

    service.embed(
        payload_path=args.payload,
        carrier_path=args.carrier,
        output_path=args.output,
        password=password,
        force=args.force,
        show_progress=True,
        verbose=args.verbose,
    )

    print(f"[+] Payload successfully embedded: {args.output}")
    return 0


def run_extract(args: argparse.Namespace) -> int:
    """
    Run the extraction operation.
    """
    password = get_password(args.password, confirm=False)
    service = StegoService()

    output_path = service.extract(
        carrier_path=args.carrier,
        output_directory=args.output,
        password=password,
        force=args.force,
        show_progress=True,
        verbose=args.verbose,
    )

    print(f"[+] Payload successfully extracted: {output_path}")
    return 0


def main() -> int:
    """
    Main GhostWire entry point.
    """
    parser = build_parser()

    try:
        args = parser.parse_args()

        if args.command == "capacity":
            return run_capacity(args)

        if args.command == "embed":
            return run_embed(args)

        if args.command == "extract":
            return run_extract(args)

        parser.error("A valid command is required.")

    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.", file=sys.stderr)
        return 130

    except ValidationError as exc:
        print(f"[!] Validation error: {exc}", file=sys.stderr)
        return 1

    except ValueError as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1

    except FileNotFoundError as exc:
        print(f"[!] File not found: {exc}", file=sys.stderr)
        return 1

    except Exception as exc:
        print(f"[!] GhostWire error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())