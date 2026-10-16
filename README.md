# GhostWire

> Hide. Encrypt. Transmit. Undetected.

GhostWire is an advanced Python steganography and steganalysis framework engineered to securely conceal encrypted, compressed payloads inside digital media (PNG images and WAV audio) using randomized Least Significant Bit (LSB) embedding, authenticated AES-256-GCM encryption, PBKDF2 key derivation, multi-carrier splitting, and forensic steganalysis detection.

---

## Features

### Supported Media Carriers
- **PNG Images (RGB / RGBA)**: 1-bit LSB embedding across R, G, and B color channels. The alpha channel is preserved untouched.
- **WAV Audio (8/16/24/32-bit PCM)**: Sample-level 1-bit LSB embedding across audio channels (mono/stereo) with an inaudible perceptual noise floor (~ -96 dB).

### Security & Cryptography
- **Triple-Factor Salted Randomizer**: Position generation is seeded using `SHA256(password + carrier_fingerprint + random_salt)`. Embedding the same payload into the same carrier with the same password yields completely different, non-repeating pixel/sample positions every time.
- **Invariant Carrier Fingerprinting**: Computes a SHA-256 hash across MSBs (`byte & 0xFE`). The fingerprint is invariant under LSB modifications, binding extraction strictly to the original carrier.
- **Collision-Free Position Reservation**: Guarantees zero overlap between the bootstrap packet header and payload positions.
- **AES-256-GCM Authenticated Encryption**: Military-grade authenticated cipher providing confidentiality, authenticity, and tamper detection.
- **PBKDF2 Key Derivation**: 600,000 SHA-256 iterations with unique 16-byte random salts.
- **SHA-256 Integrity Verification**: Cryptographic payload hash verified with constant-time comparison (`hmac.compare_digest`).
- **High-Efficiency Compression**: Pre-encryption `zlib` compression (level 9) minimizing carrier footprint.

### Multi-Carrier Splitting
- **Proportional Capacity Partitioning**: Large payloads are partitioned dynamically according to the individual capacities of each supplied carrier.
- **Mixed Media Support**: Combine images and audio tracks into a unified bundle (e.g., 2 PNGs + 1 WAV).
- **Bundle Integrity & Sequencing**: Cryptographic 16-byte bundle UUIDs and sequence indices ensure complete reassembly and detect missing or duplicate fragments.

### Forensic Steganalysis Suite
- **Chi-Square ($\chi^2$) PoVs Analysis**: Tests adjacent Pairs of Values for artificial frequency equalization.
- **Sample Pair Analysis (SPA)**: Calculates adjacent sample transition probabilities to estimate hidden data ratios.
- **Spatial / Temporal Block Entropy**: Evaluates local Shannon entropy variance across blocks to detect clustered or sequential steganography.
- **Visual Bitplane Dumper**: Exports high-contrast 1-bit LSB maps (`--dump-lsb`) for visual inspection.

### Command-Line Interface (CLI)
- **`capacity`**: Instant capacity and metadata inspection for PNG and WAV files.
- **`embed`**: Single carrier embedding with password confirmation, `--force`, and `--verbose`.
- **`extract`**: Recovery to target directories or explicit filenames with single or multi-carrier auto-detection.
- **`split-embed`**: Proportional multi-carrier embedding across 2 or more media carriers.
- **`split-extract`**: Re-assembly and extraction from multi-carrier bundles.
- **`analyze`**: Forensic steganalysis report with Chi-Square, SPA, entropy metrics, and visual LSB map export.
- **Live Progress Tracking**: Integrated `tqdm` progress bars for operations exceeding 50 KB.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/SakshamDhakarey893/Ghostwire.git
cd Ghostwire
```

Create and activate a virtual environment:

### Windows
```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage Guide

### 1. Inspect Carrier Capacity

Before embedding, check how much data your carrier image or audio file can hold:

```bash
python ghostwire.py capacity -c carriers/images/photo.png
```

---

### 2. Embed a Secret Payload (Single Carrier)

Hide any file inside an image or audio track:

```bash
python ghostwire.py embed \
  -p payloads/secret.pdf \
  -c carriers/images/landscape.png \
  -o output/stego_landscape.png
```

Options:
- `--password`: Pass password directly or omit for a hidden prompt.
- `-f / --force`: Overwrite output file if it already exists.
- `-v / --verbose`: Print diagnostic details (fingerprint, salt, bit allocations).

---

### 3. Extract and Decrypt a Hidden Payload

Recover the hidden file from a stego carrier:

```bash
# Extract to a directory (preserves original filename)
python ghostwire.py extract \
  -c output/stego_landscape.png \
  -o output/recovered/

# Or extract directly to an explicit target filename
python ghostwire.py extract \
  -c output/stego_landscape.png \
  -o output/recovered_document.pdf \
  --password "CorrectHorseBatteryStaple123" \
  --force
```

---

### 4. Multi-Carrier Payload Splitting (Proportional Distribution)

When a payload is too large for a single carrier, or for operational security, split it across multiple image and audio files:

```bash
python ghostwire.py split-embed \
  -p payloads/large_database.zip \
  -c carriers/images/photo1.png carriers/audio/song.wav carriers/images/photo2.png \
  -o output/stego1.png output/stego2.wav output/stego3.png \
  --password "MultiCarrierSecretKey"
```

To reconstruct the original payload, supply all carrier parts (in any order):

```bash
python ghostwire.py split-extract \
  -c output/stego3.png output/stego1.png output/stego2.wav \
  -o output/recovered_database.zip \
  --password "MultiCarrierSecretKey"
```

*(Note: Standard `ghostwire extract -c stego1.png stego2.wav stego3.png -o output/` also automatically detects and reconstructs multi-carrier bundles!)*

---

### 5. Forensic Steganalysis & LSB Map Export

Audit an image or audio file for suspicious hidden data, sequential LSB anomalies, or tampering:

```bash
python ghostwire.py analyze -c suspicious_image.png --dump-lsb lsb_visual_map.png --verbose
```

**Example Output:**
```text
[*] Running Steganalysis on: C:\Users\...\suspicious_image.png...
[+] Media Type: Image (PNG)

[+] Forensic Metrics:
    1. Chi-Square (Pairs of Values) Statistic: 118.42 (DoF: 127)
       -> p-value: 0.697412
    2. LSB Transition Rate: 0.3218 (Uniform random baseline: 0.5000)
       -> Estimated Embedding Rate: 10.9%
    3. Local Block LSB Entropy: 0.8924 / 1.0000
       -> Spatial Variance: 0.001245

[+] Detailed Findings:
    - Chi-Square PoVs p-value (0.6974) reflects natural intensity distribution.
    - LSB transition rate (0.3218) shows healthy spatial/temporal sample correlation.
    - Block entropy variance (0.001245) indicates uniform spatial distribution.

[+] Forensic Verdict: CLEAN (No sequential steganographic anomalies detected)
[+] Confidence Level: HIGH
[+] Visual LSB Bitplane Map exported: C:\Users\...\lsb_visual_map.png
```

---

## Capacity Estimation Formulas

| Carrier Type | Raw Capacity Formula | Usable Capacity (Rule of Thumb) |
| :--- | :--- | :--- |
| **PNG Image** | $\text{Width} \times \text{Height} \times 3 \text{ bits}$ | $\approx \frac{\text{Width} \times \text{Height} \times 3}{8} - 150 \text{ bytes}$ |
| **WAV Audio** | $\text{Frames} \times \text{Channels} \text{ bits}$ | $\approx \frac{\text{Frames} \times \text{Channels}}{8} - 150 \text{ bytes}$ |

---

## Security Model & Steganalysis Resistance

1. **Carrier Re-Use Immunity**:
   Unlike standard tools that reuse static seeds, GhostWire binds embedding positions to an invariant MSB hash of the carrier plus a cryptographically generated 16-byte random salt.
2. **Chi-Square Uniformity**:
   Because the payload is encrypted with AES-256-GCM prior to embedding, the embedded bitstream has maximum entropy ($p \approx 0.5$). Combined with PRNG sampling across the entire carrier, modifications are uniformly distributed rather than clustered in top scanlines, defeating naive visual, frequency, and sample-pair steganalysis.
3. **Tamper Proofing**:
   Any modification to the stego carrier (flipping a bit or altering audio samples) will cause either bootstrap header validation to fail or AES-256-GCM authentication tag verification to fail (`InvalidTag`), preventing execution of corrupted or tampered payloads.

---

## Running the Test Suite

GhostWire includes a 73-test automated suite covering cryptography, framing, steganography engines, capacity estimation, multi-carrier splitting, steganalysis, and CLI integration.

```bash
pytest -v
```

---

## Disclaimer

GhostWire is designed and intended strictly for educational, research, authorized penetration testing, and defensive cybersecurity purposes. Users are responsible for complying with all applicable local, national, and international laws.

---

## License

MIT License. See [LICENSE](LICENSE) for details.