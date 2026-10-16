# GhostWire

> Hide. Encrypt. Transmit. Undetected.

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-73%20passed%20(100%25)-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/cipher-AES--256--GCM-red.svg)](core/crypto.py)
[![Version](https://img.shields.io/badge/version-2.1.0-blueviolet.svg)](ghostwire.py)

GhostWire is an enterprise-grade steganography and steganalysis framework written in Python. It conceals encrypted, compressed payloads inside digital media (PNG images and WAV audio tracks) using randomized Least Significant Bit (LSB) embedding, authenticated AES-256-GCM encryption, PBKDF2 key derivation, multi-carrier payload splitting, and an empirical forensic steganalysis suite.

---

## Key Features

### 1. Supported Media Carriers
- **PNG Images (`RGB` / `RGBA`)**: 1-bit LSB embedding across Red, Green, and Blue color channels. The alpha channel is preserved untouched to maintain transparency rendering.
- **WAV Audio (`8`, `16`, `24`, and `32-bit PCM`)**: Sample-level 1-bit LSB embedding across mono and multi-channel audio tracks with an imperceptible perceptual noise floor ($\sim -96\text{ dB}$).

### 2. Multi-Carrier Payload Splitting (v2.1)
- **Heterogeneous Bundling**: Seamlessly partition large encrypted payloads proportionally across multiple carriers (e.g. 2 PNG images and 1 WAV audio file in a single operation).
- **Proportional Capacity Allocation**: Automatically calculates each carrier's usable volume and splits payload data dynamically to avoid overflowing any individual file.
- **Strict Bundle Identification**: Uses 16-byte random bundle UUIDs, chunk sequence numbers, and total part validation to guarantee zero duplicate or missing parts.
- **Global Payload Integrity**: Verifies SHA-256 integrity over the entire reassembled payload upon extraction.

### 3. Forensic Steganalysis Suite (v2.1)
- **Chi-Square Pairs of Values (PoVs)**: Implements the Westfeld & Pfitzmann statistical attack with exact Wilson-Hilferty normal approximation to calculate empirical $p$-values.
- **Sample Pair Analysis (SPA)**: Evaluates adjacent sample transition rates against the Dumitrescu-Wu-Wang natural correlation baseline ($\approx 0.25 - 0.35$).
- **Shannon Block Entropy Variance**: Measures local spatial/temporal LSB entropy and variance to detect clustered or sequential anomalies.
- **Visual LSB Bitplane Map Export**: Exports visual 1-bit LSB maps (`--dump-lsb`) for visual inspection of image bitplanes.

### 4. Military-Grade Cryptography & Anti-Detection
- **Triple-Factor Salted Randomizer**: Embedding positions are determined by a PRNG seeded with $\text{SHA-256}(\text{password} + \text{carrier\_fingerprint} + \text{random\_salt})$. Re-embedding the same payload into the same carrier with the same password produces entirely distinct, non-repeating positions every time.
- **Invariant Carrier Fingerprinting**: Derives a SHA-256 hash strictly from carrier MSBs (`byte & 0xFE`). The fingerprint is invariant under LSB modifications, binding extraction strictly to the authentic carrier file.
- **Zero-Collision Position Reservation**: Guarantees zero overlap between the bootstrap packet header positions and payload data positions.
- **AES-256-GCM Authenticated Encryption**: Provides confidentiality, authenticity, and tamper detection with 12-byte random nonces and 16-byte authentication tags.
- **PBKDF2 Key Derivation**: 600,000 SHA-256 iterations with unique 16-byte random salts.
- **Constant-Time Verification**: Verifies SHA-256 integrity digests with `hmac.compare_digest` to prevent timing side-channel attacks.
- **High-Efficiency Compression**: Pre-encryption `zlib` compression (level 9) minimizing carrier footprint.

### 5. Developer & Operational Experience
- **Interactive Secure Prompts**: Password prompts use `getpass` with hidden entry and confirmation.
- **Live Progress Tracking**: Integrated `tqdm` progress bars with automated TTY detection and fallback.
- **Flexible Extraction**: Automatic multi-carrier detection in `extract` or explicit assembly via `split-extract`.
- **Safety Overwrite Controls**: Prevents accidental file loss with `-f/--force` overwrite guards.
- **Diagnostic Logging**: Verbose logging (`-v/--verbose`) for in-depth cryptographic and bit-allocation forensics.

---

## Project Structure

```text
Ghostwire/
├── carriers/
│   ├── audio/              # Sample WAV carrier files
│   └── images/             # Sample PNG carrier files
├── core/
│   ├── audio_stego.py      # WAV PCM LSB steganography engine
│   ├── compression.py      # zlib pre-encryption compression
│   ├── crypto.py           # AES-256-GCM cipher & PBKDF2 key derivation
│   ├── image_stego.py      # PNG image LSB steganography engine
│   ├── integrity.py        # SHA-256 payload integrity hashing
│   ├── metadata.py         # Binary metadata envelope (filename, size, hash)
│   ├── multi_carrier.py    # Multi-carrier payload chunking & reassembly
│   ├── packet.py           # Protocol v1/v2 packet framing & bootstrap headers
│   ├── payload.py          # High-level payload packaging pipeline
│   ├── randomizer.py       # Triple-factor salted PRNG position generator
│   ├── steganalysis.py     # Chi-Square, Sample Pair Analysis & LSB exporter
│   ├── stego_service.py    # Single-carrier orchestration service
│   ├── utils.py            # Coordinate math & bit manipulation utilities
│   └── validation.py       # Input validation & security constraints
├── tests/                  # 73-test automated test suite (100% pass rate)
│   ├── test_audio_stego.py
│   ├── test_cli.py
│   ├── test_compression.py
│   ├── test_crypto.py
│   ├── test_end_to_end.py
│   ├── test_force_and_capacity.py
│   ├── test_image_stego.py
│   ├── test_integrity.py
│   ├── test_metadata.py
│   ├── test_multi_carrier.py
│   ├── test_packet.py
│   ├── test_payload.py
│   ├── test_randomizer.py
│   ├── test_randomizer_v2.py
│   ├── test_security.py
│   ├── test_steganalysis.py
│   ├── test_steganalysis_engine.py
│   └── test_stego_service.py
├── ghostwire.py            # Unified CLI entry point
├── requirements.txt        # Runtime dependencies
├── LICENSE                 # MIT License
└── README.md               # Framework documentation
```

---

## Architecture & Data Flow

### Single-Carrier Pipeline

```text
Secret Payload File
         ↓
SHA-256 Integrity Digest (32 bytes)
         ↓
zlib Compression (Level 9)
         ↓
AES-256-GCM Authenticated Encryption (12-byte Nonce + 16-byte Tag)
         ↓
Binary Metadata Envelope (Filename, Size, Hash)
         ↓
Protocol v2 Framing (Magic 'GW' + Version 2 + 16-byte Random Salt + Size)
         ↓
Triple-Factor Salted Position Generation (Password + MSB Fingerprint + Salt)
         ↓
Randomized LSB Embedding (Zero Collision Reservation)
         ↓
Stego Media Carrier (PNG / WAV)
```

### Protocol v2 Bootstrap Header Layout (24 Bytes)

```text
+--------------+---------------+---------------+--------------------+------------------------+
| Magic (2B)   | Version (1B)  | Flags (1B)    | Packet Size (4B)   | Position Salt (16B)    |
| b"GW"        | 0x02          | 0x00          | uint32 (Big-Endian)| Cryptographic Salt     |
+--------------+---------------+---------------+--------------------+------------------------+
```

### Multi-Carrier Chunk Framing Layout (62 Bytes + Payload)

```text
+-------------+------------------+-----------------+------------------+-------------------+--------------------+------------------+--------------------+
| Magic (4B)  | Bundle ID (16B)  | Part Index (2B) | Total Parts (2B) | Filename Len (2B) | File SHA-256 (32B) | Chunk Len (4B)   | Variable Chunk Data|
| b"GWMC"     | Random UUID      | uint16          | uint16           | uint16            | SHA-256 Digest     | uint32           | Encrypted Fragment |
+-------------+------------------+-----------------+------------------+-------------------+--------------------+------------------+--------------------+
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/SakshamDhakarey893/Ghostwire.git
cd Ghostwire
```

Create and activate a virtual environment:

### Windows
```powershell
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

## CLI Usage Guide

### 1. Capacity & Metadata Inspection (`capacity`)

Inspect the maximum steganographic payload capacity of any PNG image or WAV audio carrier:

```bash
python ghostwire.py capacity -c carriers/images/landscape.png
```

**Example Output:**
```text
[+] Carrier File: C:\...\carriers\images\landscape.png
    - Media Type: Image (PNG)
    - Dimensions: 1920 x 1080 pixels
    - Color Mode: RGB (Using 3 color channels)

[+] Steganographic Capacity (1-bit LSB):
    - Raw Bits:   6,220,800 bits
    - Raw Bytes:  777,600 bytes
    - Safe Size:  ~738.72 KB (accounting for metadata & encryption overhead)
```

Audio carriers work identically:

```bash
python ghostwire.py capacity -c carriers/audio/song.wav
```

---

### 2. Embed Secret Payload (`embed`)

Conceal any file (PDF, TXT, ZIP, executable, etc.) inside a single carrier:

```bash
python ghostwire.py embed \
  -p payloads/classified_report.pdf \
  -c carriers/images/landscape.png \
  -o output/stego_landscape.png
```

You will be prompted securely for an encryption password with hidden confirmation.

**Command Options:**
- `-p, --payload`: Path to the file to hide.
- `-c, --carrier`: Path to the carrier media (PNG or WAV).
- `-o, --output`: Path for the output stego file.
- `--password`: Optional command-line password (prompts securely if omitted).
- `-f, --force`: Overwrite output file if it already exists.
- `-v, --verbose`: Display detailed cryptographic diagnostic information.

---

### 3. Extract & Decrypt Payload (`extract`)

Recover the concealed file from a stego carrier:

```bash
# Extract to a directory (restores original filename from encrypted metadata)
python ghostwire.py extract \
  -c output/stego_landscape.png \
  -o output/recovered/

# Or extract directly to an explicit target filename
python ghostwire.py extract \
  -c output/stego_landscape.png \
  -o output/recovered_report.pdf \
  --password "YourSecretPassword" \
  --force
```

*(Note: If multiple carriers are supplied to `-c`, `extract` automatically detects multi-carrier bundles and delegates to the reassembly pipeline).*

---

### 4. Multi-Carrier Payload Splitting (`split-embed` & `split-extract`)

When a payload exceeds a single carrier's capacity, or for operational compartmentalization, split it across multiple heterogeneous carriers:

```bash
python ghostwire.py split-embed \
  -p payloads/archive.zip \
  -c carriers/images/photo1.png carriers/audio/track.wav carriers/images/photo2.png \
  -o output/stego1.png output/stego2.wav output/stego3.png \
  --password "MultiCarrierSecretKey"
```

Reassemble and decrypt the original payload by providing all bundle carriers (in any order):

```bash
python ghostwire.py split-extract \
  -c output/stego3.png output/stego1.png output/stego2.wav \
  -o output/restored_archive.zip \
  --password "MultiCarrierSecretKey"
```

---

### 5. Forensic Steganalysis & LSB Map Export (`analyze`)

Audit any PNG or WAV file to test for statistical anomalies, sequential LSB tampering, or hidden payloads:

```bash
python ghostwire.py analyze \
  -c output/stego_landscape.png \
  --dump-lsb output/lsb_plane.png \
  --verbose
```

**Example Output:**
```text
[*] Running Steganalysis on: C:\...\output\stego_landscape.png...
[+] Media Type: Image (PNG)

[+] Forensic Metrics:
    1. Chi-Square (Pairs of Values) Statistic: 114.32 (DoF: 127)
       -> p-value: 0.784102
    2. LSB Transition Rate: 0.3245 (Uniform random baseline: 0.5000)
       -> Estimated Embedding Rate: 12.2%
    3. Local Block LSB Entropy: 0.8951 / 1.0000
       -> Spatial Variance: 0.001180

[+] Detailed Findings:
    - Chi-Square PoVs p-value (0.7841) reflects natural intensity distribution.
    - LSB transition rate (0.3245) shows healthy spatial/temporal sample correlation.
    - Block entropy variance (0.001180) indicates uniform spatial distribution.

[+] Forensic Verdict: CLEAN (No sequential steganographic anomalies detected)
[+] Confidence Level: HIGH
[+] Visual LSB Bitplane Map exported: C:\...\output\lsb_plane.png
```

---

## Capacity Estimation Formulas

| Carrier Type | Raw Capacity Formula | Usable Capacity (Rule of Thumb) |
| :--- | :--- | :--- |
| **PNG Image** | $\text{Width} \times \text{Height} \times 3 \text{ bits}$ | $\approx \frac{\text{Width} \times \text{Height} \times 3}{8} - 150 \text{ bytes}$ |
| **WAV Audio** | $\text{Frames} \times \text{Channels} \text{ bits}$ | $\approx \frac{\text{Frames} \times \text{Channels}}{8} - 150 \text{ bytes}$ |

### Protocol Overhead Breakdown
- **Single-Carrier Protocol v2 Header**: 24 bytes
- **Multi-Carrier Chunk Envelope**: 62 bytes per carrier
- **Metadata Envelope**: ~50–80 bytes (varies with original filename length)
- **AES-256-GCM Nonce & Tag**: 28 bytes
- **PBKDF2 Salt**: 16 bytes

---

## Security Model & Steganalysis Resistance

1. **Carrier Re-Use Immunity**:
   Standard LSB tools use a static seed `SHA256(password)`, causing bits to occupy identical positions across runs. GhostWire seeds its PRNG with `SHA256(password + carrier_fingerprint + random_salt)`. Even with the same password and same carrier, every embedding operation generates a distinct, non-overlapping sequence of indices.
2. **Chi-Square & Sample Pair Uniformity**:
   Payloads are encrypted with AES-256-GCM prior to embedding, giving the bitstream maximal entropy ($p \approx 0.5$ for bit `0` vs `1`). The triple-factor PRNG disperses bits across the entire spatial/temporal domain rather than sequential scanlines, defeating naive visual, frequency, and sample-pair steganalysis.
3. **Cryptographic Tamper-Proofing**:
   Any modification to the stego carrier (flipping a single bit or clipping audio samples) causes either the bootstrap header validation or AES-256-GCM authentication tag verification to fail (`InvalidTag`), preventing execution or recovery of altered payloads.

---

## Current Scope & Constraints

- **Lossless Only**: Carriers must remain lossless. Converting a stego PNG to JPEG or a stego WAV to MP3 destroys the least significant bit plane and renders payloads unrecoverable.
- **Uncompressed PCM Audio**: Supports standard 8-bit, 16-bit, 24-bit, and 32-bit linear PCM WAV formats. Compressed WAV formats (such as ADPCM or floating-point IEEE) are strictly validated and rejected.

---

## Running the Automated Test Suite

GhostWire includes an automated test suite of **73 tests** across 18 modules covering cryptographic invariants, framing, multi-carrier splitting, steganalysis, error boundaries, and CLI operations.

Run the full test suite with verbose output:

```bash
pytest -v
```

**Test Summary:**
```text
============================= 73 passed in 8.41s =============================
```

---

## Defensive & Ethical Disclaimer

GhostWire is engineered strictly for educational purposes, cryptographic research, authorized penetration testing, and defensive digital media forensics. Users are exclusively responsible for ensuring that their use of GhostWire complies with all applicable local, state, national, and international laws.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for full terms.