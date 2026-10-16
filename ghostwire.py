"""
GhostWire
---------
Randomized LSB steganography and steganalysis command-line tool.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from core.multi_carrier import MultiCarrierService
from core.steganalysis import Steganalyzer
from core.stego_service import StegoService
from core.validation import ValidationError

VERSION = "2.1.0"
__version__ = VERSION


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
        description="GhostWire — Professional Steganography, Multi-Carrier Splitting & Steganalysis Framework",
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
    # ANALYZE (STEGANALYSIS)
    # ================================================================
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run forensic steganalysis on a PNG image or WAV audio file.",
        description="Perform Chi-Square (PoVs), Sample Pair Analysis, and LSB entropy detection.",
    )

    analyze_parser.add_argument(
        "-c",
        "--carrier",
        required=True,
        type=Path,
        help="Path to the carrier media to inspect (PNG or WAV).",
    )

    analyze_parser.add_argument(
        "--dump-lsb",
        type=Path,
        default=None,
        help="Optional output path to export visual 1-bit LSB plane map (PNG only).",
    )

    analyze_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display detailed statistical metrics and test breakdowns.",
    )

    # ================================================================
    # EMBED (SINGLE CARRIER)
    # ================================================================
    embed_parser = subparsers.add_parser(
        "embed",
        help="Hide a payload inside a single digital carrier (PNG or WAV).",
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
    # EXTRACT (SINGLE OR MULTI-CARRIER AUTO-DETECT)
    # ================================================================
    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract a hidden payload from digital carriers (PNG or WAV).",
        description=(
            "Extract and decrypt a payload from GhostWire PNG or WAV carriers."
        ),
    )

    extract_parser.add_argument(
        "-c",
        "--carrier",
        "--carriers",
        dest="carriers",
        nargs="+",
        required=True,
        type=Path,
        help="Path to one or more GhostWire carriers (PNG or WAV).",
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

    # ================================================================
    # SPLIT-EMBED (MULTI-CARRIER)
    # ================================================================
    split_embed_parser = subparsers.add_parser(
        "split-embed",
        help="Split and embed a large payload across multiple digital carriers.",
        description="Partition an encrypted payload proportionally across 2 or more PNG/WAV carriers.",
    )

    split_embed_parser.add_argument(
        "-p",
        "--payload",
        required=True,
        type=Path,
        help="Path to the secret payload file.",
    )

    split_embed_parser.add_argument(
        "-c",
        "--carriers",
        required=True,
        nargs="+",
        type=Path,
        help="List of 2 or more carrier paths (PNG or WAV).",
    )

    split_embed_parser.add_argument(
        "-o",
        "--outputs",
        required=True,
        nargs="+",
        type=Path,
        help="List of destination output paths matching each carrier.",
    )

    split_embed_parser.add_argument(
        "--password",
        default=None,
        help="Encryption password. If omitted, GhostWire prompts securely.",
    )

    split_embed_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite output files if they already exist.",
    )

    split_embed_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging.",
    )

    # ================================================================
    # SPLIT-EXTRACT (MULTI-CARRIER)
    # ================================================================
    split_extract_parser = subparsers.add_parser(
        "split-extract",
        help="Reconstruct a payload from multiple carrier fragments.",
        description="Re-assemble and decrypt a payload split across 2 or more carriers.",
    )

    split_extract_parser.add_argument(
        "-c",
        "--carriers",
        required=True,
        nargs="+",
        type=Path,
        help="List of all carrier files belonging to the multi-carrier bundle.",
    )

    split_extract_parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=Path,
        help="Output directory or specific destination file for recovered payload.",
    )

    split_extract_parser.add_argument(
        "--password",
        default=None,
        help="Decryption password. If omitted, GhostWire prompts securely.",
    )

    split_extract_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite destination file if it already exists.",
    )

    split_extract_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging.",
    )

    return parser


def run_capacity(args: argparse.Namespace) -> int:
    """Run carrier capacity query."""
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


def run_analyze(args: argparse.Namespace) -> int:
    """Run forensic steganalysis on carrier media."""
    print(f"[*] Running Steganalysis on: {args.carrier.resolve()}...")
    report = Steganalyzer.analyze_carrier(args.carrier)

    print(f"[+] Media Type: {report.media_type}")
    print("\n[+] Forensic Metrics:")
    print(f"    1. Chi-Square (Pairs of Values) Statistic: {report.chi2_stat:.2f} (DoF: {report.chi2_dof})")
    print(f"       -> p-value: {report.chi2_p_value:.6f}")
    print(f"    2. LSB Transition Rate: {report.lsb_transition_rate:.4f} (Uniform random baseline: 0.5000)")
    print(f"       -> Estimated Embedding Rate: {report.estimated_embedding_rate * 100:.1f}%")
    print(f"    3. Local Block LSB Entropy: {report.mean_chunk_entropy:.4f} / 1.0000")
    print(f"       -> Spatial Variance: {report.chunk_entropy_variance:.6f}")

    if args.verbose:
        print("\n[+] Detailed Findings:")
        for detail in report.details:
            print(f"    - {detail}")

    print(f"\n[+] Forensic Verdict: {report.verdict}")
    print(f"[+] Confidence Level: {report.confidence}")

    if args.dump_lsb:
        if args.carrier.suffix.lower() != ".png":
            print("[!] Warning: --dump-lsb visual plane export is supported for PNG images only.", file=sys.stderr)
        else:
            out_map = Steganalyzer.dump_lsb_map(args.carrier, args.dump_lsb)
            print(f"[+] Visual LSB Bitplane Map exported: {out_map.resolve()}")

    return 0


def run_embed(args: argparse.Namespace) -> int:
    """Run single carrier embedding."""
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
    """Run extraction (auto-delegating to multi-carrier if multiple carriers passed)."""
    password = get_password(args.password, confirm=False)

    if len(args.carriers) > 1:
        # Multi-carrier extraction
        mc_service = MultiCarrierService()
        output_path = mc_service.reconstruct_and_extract(
            carrier_paths=args.carriers,
            output_target=args.output,
            password=password,
            force=args.force,
            verbose=args.verbose,
            show_progress=True,
        )
        print(f"[+] Multi-carrier payload successfully reconstructed: {output_path}")
        return 0

    # Single carrier extraction
    service = StegoService()
    try:
        output_path = service.extract(
            carrier_path=args.carriers[0],
            output_directory=args.output,
            password=password,
            force=args.force,
            show_progress=True,
            verbose=args.verbose,
        )
    except ValueError as exc:
        # Check if user tried extracting a multi-carrier segment with single extract
        if "Multi-Carrier Bundle detected" in str(exc):
            raise
        # Re-raise clean error
        raise

    print(f"[+] Payload successfully extracted: {output_path}")
    return 0


def run_split_embed(args: argparse.Namespace) -> int:
    """Run multi-carrier proportional embedding."""
    password = get_password(args.password, confirm=True)
    mc_service = MultiCarrierService()

    written = mc_service.split_and_embed(
        payload_path=args.payload,
        carrier_paths=args.carriers,
        output_paths=args.outputs,
        password=password,
        force=args.force,
        verbose=args.verbose,
        show_progress=True,
    )

    print(f"[+] Multi-carrier payload successfully split and embedded across {len(written)} carriers:")
    for out in written:
        print(f"    - {out}")

    return 0


def run_split_extract(args: argparse.Namespace) -> int:
    """Run multi-carrier reassembly and extraction."""
    password = get_password(args.password, confirm=False)
    mc_service = MultiCarrierService()

    output_path = mc_service.reconstruct_and_extract(
        carrier_paths=args.carriers,
        output_target=args.output,
        password=password,
        force=args.force,
        verbose=args.verbose,
        show_progress=True,
    )

    print(f"[+] Multi-carrier payload successfully reconstructed: {output_path}")
    return 0


def main() -> int:
    """Main GhostWire entry point."""
    parser = build_parser()

    try:
        args = parser.parse_args()

        if args.command == "capacity":
            return run_capacity(args)

        if args.command == "analyze":
            return run_analyze(args)

        if args.command == "embed":
            return run_embed(args)

        if args.command == "extract":
            return run_extract(args)

        if args.command == "split-embed":
            return run_split_embed(args)

        if args.command == "split-extract":
            return run_split_extract(args)

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