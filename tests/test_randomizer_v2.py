"""
Tests for GhostWire v2 Randomizer: carrier fingerprinting, random salt, and exclusions.
"""

import os
from pathlib import Path
from PIL import Image
import pytest

from core.image_stego import ImageStego
from core.randomizer import Randomizer


def test_randomizer_carrier_fingerprint_changes_positions():
    """Different carriers with the same password must produce different positions."""
    password = "SuperSecretPassword123"
    fp_a = b"FINGERPRINT_CARRIER_A_12345678"
    fp_b = b"FINGERPRINT_CARRIER_B_87654321"

    r_a = Randomizer(password, carrier_fingerprint=fp_a)
    r_b = Randomizer(password, carrier_fingerprint=fp_b)

    pos_a = r_a.generate_positions(total_pixels=10000, required_bits=100)
    pos_b = r_b.generate_positions(total_pixels=10000, required_bits=100)

    assert pos_a != pos_b


def test_randomizer_salt_changes_positions():
    """Different salts for the same carrier must produce different positions."""
    password = "SuperSecretPassword123"
    fp = b"CONSTANT_CARRIER_FINGERPRINT_01"
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)

    r1 = Randomizer(password, carrier_fingerprint=fp, salt=salt1)
    r2 = Randomizer(password, carrier_fingerprint=fp, salt=salt2)

    pos1 = r1.generate_positions(total_pixels=10000, required_bits=100)
    pos2 = r2.generate_positions(total_pixels=10000, required_bits=100)

    assert pos1 != pos2


def test_randomizer_deterministic_with_identical_inputs():
    """Identical password, carrier fingerprint, and salt must produce identical positions."""
    password = "ConsistentPassword"
    fp = b"CARRIER_FINGERPRINT_MATCH"
    salt = b"0123456789abcdef"

    r1 = Randomizer(password, carrier_fingerprint=fp, salt=salt)
    r2 = Randomizer(password, carrier_fingerprint=fp, salt=salt)

    pos1 = r1.generate_positions(total_pixels=50000, required_bits=250)
    pos2 = r2.generate_positions(total_pixels=50000, required_bits=250)

    assert pos1 == pos2


def test_randomizer_zero_collision_with_exclusions():
    """Payload positions must never collide with reserved header positions."""
    password = "NoCollisionPassword"
    fp = b"FINGERPRINT_NO_COLLIDE"
    salt = b"fixed_salt_16_b!"

    r_header = Randomizer(password, carrier_fingerprint=fp)
    header_pos = r_header.generate_positions(total_pixels=5000, required_bits=192)

    r_payload = Randomizer(password, carrier_fingerprint=fp, salt=salt)
    payload_pos = r_payload.generate_positions(
        total_pixels=5000,
        required_bits=1000,
        exclude_positions=header_pos,
    )

    header_set = set(header_pos)
    payload_set = set(payload_pos)

    assert len(header_pos) == 192
    assert len(payload_pos) == 1000
    assert len(header_set.intersection(payload_set)) == 0


def test_image_index_to_coord_math():
    """index_to_coord must match (y * width + x) * 3 + channel."""
    width = 100
    for channel in range(3):
        for y in (0, 10, 50):
            for x in (0, 25, 99):
                idx = (y * width + x) * 3 + channel
                calc_x, calc_y, calc_c = ImageStego.index_to_coord(idx, width)
                assert (calc_x, calc_y, calc_c) == (x, y, channel)
