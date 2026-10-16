"""
GhostWire Random Position Generator

Generates deterministic random pixel positions
using a password-derived seed.
"""

import hashlib
import random
from typing import List


class Randomizer:
    """
    Generates reproducible random positions
    based on a user password.
    """

    def __init__(self, password: str):
        self.password = password
        self.seed = self._generate_seed()

    def _generate_seed(self) -> int:
        """
        Generate an integer seed from the password.
        """
        hash_bytes = hashlib.sha256(
            self.password.encode("utf-8")
        ).digest()

        return int.from_bytes(hash_bytes, byteorder="big")

    def generate_positions(
        self,
        total_pixels: int,
        required_bits: int
    ) -> List[int]:
        """
        Generate unique random pixel positions.

        Args:
            total_pixels: Total pixels available.
            required_bits: Number of bits to embed.

        Returns:
            List of pixel indices.
        """

        if required_bits > total_pixels:
            raise ValueError(
                "Not enough pixels available for payload."
            )

        rng = random.Random(self.seed)

        positions = rng.sample(
            range(total_pixels),
            required_bits
        )

        return positions