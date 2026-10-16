import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.randomizer import Randomizer


def test_randomizer():
    password = "ghostwire2026"

    r1 = Randomizer(password)
    r2 = Randomizer(password)

    pos1 = r1.generate_positions(
        total_pixels=1000,
        required_bits=20
    )

    pos2 = r2.generate_positions(
        total_pixels=1000,
        required_bits=20
    )

    assert pos1 == pos2