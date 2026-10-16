"""
GhostWire Random Position Generator

Generates deterministic, unique random carrier positions based on
a user password, an invariant carrier fingerprint, and an optional random salt.
"""

from __future__ import annotations

import hashlib
import random
from typing import Sequence


class Randomizer:
    """
    Generates reproducible random carrier positions based on password,
    carrier fingerprint, and an optional random salt.
    """

    def __init__(
        self,
        password: str,
        carrier_fingerprint: bytes | None = None,
        salt: bytes | None = None,
    ):
        if not password:
            raise ValueError("Password cannot be empty.")

        self.password = password
        self.carrier_fingerprint = carrier_fingerprint
        self.salt = salt
        self.seed = self._generate_seed()

    def _generate_seed(self) -> int:
        """
        Generate a 256-bit integer seed from password, carrier fingerprint, and salt.

        Formula:
            seed_material = password.encode('utf-8') + carrier_fingerprint + salt
        """
        hasher = hashlib.sha256(self.password.encode("utf-8"))

        if self.carrier_fingerprint is not None:
            hasher.update(self.carrier_fingerprint)

        if self.salt is not None:
            hasher.update(self.salt)

        return int.from_bytes(hasher.digest(), byteorder="big")

    def generate_positions(
        self,
        total_pixels: int,
        required_bits: int,
        exclude_positions: Sequence[int] | set[int] | None = None,
    ) -> list[int]:
        """
        Generate unique pseudo-random position indices.

        Args:
            total_pixels: Total carrier positions (capacity) available.
            required_bits: Number of positions needed.
            exclude_positions: Optional set/sequence of positions that cannot
                               be selected (e.g. reserved header positions).

        Returns:
            List of unique integer positions.

        Raises:
            ValueError: If required_bits exceeds available carrier positions.
        """
        exclude_set = set(exclude_positions) if exclude_positions is not None else None
        available_count = total_pixels - (len(exclude_set) if exclude_set else 0)

        if required_bits > available_count:
            raise ValueError(
                f"Not enough carrier positions available. Required: {required_bits}, "
                f"available: {available_count} (out of {total_pixels} total)."
            )

        rng = random.Random(self.seed)

        if not exclude_set:
            return rng.sample(range(total_pixels), required_bits)

        # Rejection sampling with fast set lookup when exclusions exist
        selected: list[int] = []
        seen = set(exclude_set)
        while len(selected) < required_bits:
            cand = rng.randrange(total_pixels)
            if cand not in seen:
                seen.add(cand)
                selected.append(cand)

        return selected