"""
GhostWire Steganalysis Module
-----------------------------
Detects anomalies, statistical artifacts, and hidden LSB steganography
in digital image and audio media.

Algorithms implemented:
1. Chi-Square (Pairs of Values - PoVs) Analysis (Westfeld & Pfitzmann)
2. Sample Pair Transition Analysis (Dumitrescu-Wu-Wang metric)
3. Spatial / Temporal Block LSB Entropy & Variance
4. Visual LSB Bitplane Map Extraction
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
from typing import Any
import wave

import numpy as np
from PIL import Image


@dataclass(frozen=True)
class SteganalysisReport:
    """Forensic report containing metrics and steganography detection verdict."""

    carrier_path: str
    media_type: str
    chi2_stat: float
    chi2_dof: int
    chi2_p_value: float
    lsb_transition_rate: float
    estimated_embedding_rate: float
    mean_chunk_entropy: float
    chunk_entropy_variance: float
    verdict: str
    confidence: str
    details: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "carrier_path": self.carrier_path,
            "media_type": self.media_type,
            "chi2_stat": round(self.chi2_stat, 4),
            "chi2_dof": self.chi2_dof,
            "chi2_p_value": round(self.chi2_p_value, 6),
            "lsb_transition_rate": round(self.lsb_transition_rate, 4),
            "estimated_embedding_rate": round(self.estimated_embedding_rate, 4),
            "mean_chunk_entropy": round(self.mean_chunk_entropy, 4),
            "chunk_entropy_variance": round(self.chunk_entropy_variance, 6),
            "verdict": self.verdict,
            "confidence": self.confidence,
            "details": self.details,
        }


def _chi2_survival(stat: float, dof: int) -> float:
    """
    Calculate upper-tail p-value for chi-square distribution using the
    Wilson-Hilferty normal approximation. Accurate and zero-dependency.
    """
    if dof <= 0 or stat <= 0:
        return 1.0

    q = 2.0 / (9.0 * dof)
    z = ((stat / dof) ** (1.0 / 3.0) - (1.0 - q)) / math.sqrt(q)
    p = 0.5 * math.erfc(z / math.sqrt(2.0))
    return max(0.0, min(1.0, p))


def _shannon_entropy(bits: np.ndarray) -> float:
    """Calculate Shannon entropy for a 1D sequence of bits (0 or 1)."""
    if bits.size == 0:
        return 0.0

    p1 = float(np.mean(bits))
    p0 = 1.0 - p1

    entropy = 0.0
    if p0 > 0.0:
        entropy -= p0 * math.log2(p0)
    if p1 > 0.0:
        entropy -= p1 * math.log2(p1)

    return entropy


class Steganalyzer:
    """Forensic steganalysis engine for PNG images and WAV audio."""

    @staticmethod
    def analyze_carrier(carrier_path: str | Path) -> SteganalysisReport:
        """
        Run complete steganalysis suite on a PNG image or WAV audio file.
        """
        path = Path(carrier_path)
        if not path.is_file():
            raise FileNotFoundError(f"Carrier file not found: {path}")

        ext = path.suffix.lower()
        if ext == ".png":
            return Steganalyzer.analyze_image(path)
        if ext == ".wav":
            return Steganalyzer.analyze_audio(path)

        raise ValueError(
            f"Unsupported carrier for steganalysis: '{ext}'. Supported: .png, .wav"
        )

    @staticmethod
    def analyze_image(image_path: Path) -> SteganalysisReport:
        """Analyze an image using Chi-Square PoVs and spatial transition analysis."""
        image = Image.open(image_path).convert("RGB")
        arr = np.array(image, dtype=np.uint8)

        # Flatten RGB channels
        flat_channels = arr.reshape(-1, 3)

        # 1. Chi-Square Pairs of Values (PoVs) test across all color channels
        flat_all = arr.flatten().astype(np.int64)
        counts = np.bincount(flat_all, minlength=256)
        even_c = counts[0::2]
        odd_c = counts[1::2]
        pair_totals = even_c + odd_c
        mask = pair_totals > 10

        if np.any(mask):
            observed_even = even_c[mask]
            expected = pair_totals[mask] / 2.0
            chi2_stat = float(np.sum((observed_even - expected) ** 2 / expected))
            chi2_dof = int(np.sum(mask)) - 1
            chi2_p = _chi2_survival(chi2_stat, chi2_dof)
        else:
            chi2_stat, chi2_dof, chi2_p = 0.0, 127, 1.0

        # 2. Adjacent Sample Pair LSB Transition Rate
        lsb_plane = arr & 1
        # Horizontal and vertical LSB transitions
        h_diff = np.abs(lsb_plane[:, :-1, :] - lsb_plane[:, 1:, :])
        v_diff = np.abs(lsb_plane[:-1, :, :] - lsb_plane[1:, :, :])
        transition_rate = float((np.mean(h_diff) + np.mean(v_diff)) / 2.0)

        # Baseline transition rate for natural images is typically ~0.25 - 0.35
        # Fully random LSBs approach 0.50
        est_embedding_rate = max(0.0, min(1.0, (transition_rate - 0.30) / 0.20))

        # 3. Block LSB Entropy & Variance across 8 horizontal slices
        height, width, _ = arr.shape
        num_blocks = 8
        chunk_height = max(1, height // num_blocks)
        block_entropies = []
        for i in range(num_blocks):
            sub_arr = lsb_plane[i * chunk_height : (i + 1) * chunk_height, :, :]
            block_entropies.append(_shannon_entropy(sub_arr.flatten()))

        mean_entropy = float(np.mean(block_entropies))
        entropy_var = float(np.var(block_entropies))

        # 4. Formulate Verdict
        verdict, confidence, details = Steganalyzer._evaluate_verdict(
            chi2_stat, chi2_dof, chi2_p, transition_rate, est_embedding_rate, entropy_var
        )

        return SteganalysisReport(
            carrier_path=str(image_path),
            media_type="Image (PNG)",
            chi2_stat=chi2_stat,
            chi2_dof=chi2_dof,
            chi2_p_value=chi2_p,
            lsb_transition_rate=transition_rate,
            estimated_embedding_rate=est_embedding_rate,
            mean_chunk_entropy=mean_entropy,
            chunk_entropy_variance=entropy_var,
            verdict=verdict,
            confidence=confidence,
            details=details,
        )

    @staticmethod
    def analyze_audio(audio_path: Path) -> SteganalysisReport:
        """Analyze a WAV audio carrier for LSB anomalies."""
        with wave.open(str(audio_path), "rb") as wf:
            params = wf.getparams()
            raw_frames = wf.readframes(params.nframes)

        # Extract primary sample bytes (LSB bytes in little-endian PCM)
        arr = np.frombuffer(raw_frames, dtype=np.uint8)
        sampwidth = params.sampwidth
        sample_lsb_bytes = arr[::sampwidth].astype(np.int64)

        # 1. Chi-Square PoVs
        counts = np.bincount(sample_lsb_bytes, minlength=256)
        even_c = counts[0::2]
        odd_c = counts[1::2]
        pair_totals = even_c + odd_c
        mask = pair_totals > 10

        if np.any(mask):
            observed_even = even_c[mask]
            expected = pair_totals[mask] / 2.0
            chi2_stat = float(np.sum((observed_even - expected) ** 2 / expected))
            chi2_dof = int(np.sum(mask)) - 1
            chi2_p = _chi2_survival(chi2_stat, chi2_dof)
        else:
            chi2_stat, chi2_dof, chi2_p = 0.0, 127, 1.0

        # 2. Adjacent Sample LSB Transition Rate
        lsbs = sample_lsb_bytes & 1
        diffs = np.abs(lsbs[:-1] - lsbs[1:])
        transition_rate = float(np.mean(diffs)) if diffs.size > 0 else 0.0
        est_embedding_rate = max(0.0, min(1.0, (transition_rate - 0.28) / 0.22))

        # 3. Block Entropy across 8 audio chunks
        chunk_len = max(1, lsbs.size // 8)
        block_entropies = []
        for i in range(8):
            sub_chunk = lsbs[i * chunk_len : (i + 1) * chunk_len]
            block_entropies.append(_shannon_entropy(sub_chunk))

        mean_entropy = float(np.mean(block_entropies))
        entropy_var = float(np.var(block_entropies))

        verdict, confidence, details = Steganalyzer._evaluate_verdict(
            chi2_stat, chi2_dof, chi2_p, transition_rate, est_embedding_rate, entropy_var
        )

        return SteganalysisReport(
            carrier_path=str(audio_path),
            media_type=f"Audio (WAV {params.framerate}Hz, {params.nchannels}ch, {params.sampwidth*8}bit)",
            chi2_stat=chi2_stat,
            chi2_dof=chi2_dof,
            chi2_p_value=chi2_p,
            lsb_transition_rate=transition_rate,
            estimated_embedding_rate=est_embedding_rate,
            mean_chunk_entropy=mean_entropy,
            chunk_entropy_variance=entropy_var,
            verdict=verdict,
            confidence=confidence,
            details=details,
        )

    @staticmethod
    def _evaluate_verdict(
        chi2_stat: float,
        chi2_dof: int,
        chi2_p: float,
        transition_rate: float,
        est_rate: float,
        entropy_var: float,
    ) -> tuple[str, str, list[str]]:
        """Compute forensic verdict and diagnostic bullet points."""
        details: list[str] = []

        is_suspicious_chi2 = chi2_p > 0.95
        is_suspicious_transition = transition_rate > 0.46
        is_sequential_clustering = entropy_var > 0.08

        if is_suspicious_chi2:
            details.append(
                f"Chi-Square PoVs p-value is extremely high ({chi2_p:.4f}), indicating paired intensity equalization."
            )
        else:
            details.append(
                f"Chi-Square PoVs p-value ({chi2_p:.4f}) reflects natural intensity distribution."
            )

        if is_suspicious_transition:
            details.append(
                f"LSB transition rate ({transition_rate:.4f}) is abnormally close to uniform random noise (0.50)."
            )
        else:
            details.append(
                f"LSB transition rate ({transition_rate:.4f}) shows healthy spatial/temporal sample correlation."
            )

        if is_sequential_clustering:
            details.append(
                f"High block entropy variance ({entropy_var:.6f}) suggests clustered sequential embedding."
            )
        else:
            details.append(
                f"Block entropy variance ({entropy_var:.6f}) indicates uniform spatial distribution."
            )

        # Composite decision logic
        if is_suspicious_chi2 and is_suspicious_transition:
            verdict = "SUSPICIOUS (High likelihood of sequential LSB steganography)"
            confidence = "HIGH"
        elif is_suspicious_chi2 or is_suspicious_transition or est_rate > 0.70:
            verdict = "SUSPICIOUS (Anomalous LSB patterns detected)"
            confidence = "MEDIUM"
        else:
            verdict = "CLEAN (No sequential steganographic anomalies detected)"
            confidence = "HIGH" if (transition_rate < 0.40 and chi2_p < 0.50) else "MEDIUM"

        return verdict, confidence, details

    @staticmethod
    def dump_lsb_map(image_path: str | Path, output_map_path: str | Path) -> Path:
        """
        Extract the 1-bit LSB plane and render it as a visual high-contrast
        grayscale image (0 -> Black, 1 -> White) for forensic visual inspection.
        """
        img = Image.open(image_path).convert("RGB")
        arr = np.array(img, dtype=np.uint8)

        # Extract LSB and amplify to 0 or 255
        lsb_visual = (arr & 1) * 255
        out_img = Image.fromarray(lsb_visual.astype(np.uint8))

        out_path = Path(output_map_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_img.save(out_path, format="PNG")
        return out_path
