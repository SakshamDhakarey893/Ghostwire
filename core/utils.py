"""
GhostWire utility helpers.

General-purpose bit manipulation and helper functions for
steganography engines.
"""

from __future__ import annotations

from typing import Sequence


def bytes_to_bits(data: bytes) -> list[int]:
    """
    Convert bytes into a list of individual bits (MSB first).

    Args:
        data: Raw byte sequence.

    Returns:
        List of integers (0 or 1).
    """
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    """
    Convert a sequence of bits back into bytes.

    Args:
        bits: Sequence of integers (0 or 1), length must be a multiple of 8.

    Returns:
        Converted bytes.

    Raises:
        ValueError: If length is not divisible by 8 or values are not 0 or 1.
    """
    if len(bits) % 8 != 0:
        raise ValueError("Bit sequence length must be divisible by 8.")

    output = bytearray()
    for index in range(0, len(bits), 8):
        byte = 0
        for bit in bits[index:index + 8]:
            if bit not in (0, 1):
                raise ValueError("Bits must contain only 0 or 1.")
            byte = (byte << 1) | bit
        output.append(byte)

    return bytes(output)
