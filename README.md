# GhostWire

> Hide. Encrypt. Transmit. Undetected.

GhostWire is an advanced Python steganography framework engineered to securely conceal encrypted, compressed payloads inside digital media (PNG images and WAV audio) using randomized Least Significant Bit (LSB) embedding, authenticated AES-256-GCM encryption, PBKDF2 key derivation, and cryptographic integrity verification.

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

### Command-Line Interface (CLI)
- **`capacity`**: Instant capacity and metadata inspection for PNG and WAV files.
- **`embed`**: Secure embedding with interactive hidden password entry, `-f/--force` overwrite, and `-v/--verbose` diagnostic mode.
- **`extract`**: Decryption and recovery to target directories or explicit filenames with overwrite control.
- **Live Progress Tracking**: Integrated `tqdm` progress bars for operations exceeding 50 KB.

---

## Architecture & Data Flow

```text
Payload File
     ↓
SHA-256 Integrity Digest
     ↓
zlib Compression (Level 9)
     ↓
AES-256-GCM Encryption (Random Nonce + Tag)
     ↓
Binary Metadata Packaging (Filename, Original Size, SHA-256)
     ↓
Protocol v2 Framing (Magic 'GW' + Version 2 + 16-byte Salt + Packet Size)
     ↓
Triple-Factor Salted Position Generation (Password + MSB Fingerprint + Salt)
     ↓
Randomized LSB Embedding (Zero Collision)
     ↓
Stego Media Carrier (PNG / WAV)
```

### Protocol v2 Packet Layout

```text
[0..1]   Magic Bytes (b"GW")
[2]      Protocol Version (0x02)
[3]      Flags (0x00)
[4..7]   Packet Size (32-bit unsigned uint)
[8..23]  Random Position Salt (16 bytes)
[24..]   Body: [4-byte Metadata Len] + [Metadata Packet] + [Salt + Nonce + Ciphertext + Tag]
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

**Example Output:**
```text
[+] Carrier File: C:\Users\...\carriers\images\photo.png
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

### 2. Embed a Secret Payload

Hide any file (PDF, TXT, ZIP, executable, etc.) inside an image or audio track:

```bash
python ghostwire.py embed \
  -p payloads/secret.pdf \
  -c carriers/images/landscape.png \
  -o output/stego_landscape.png
```

You will be prompted securely for a password. You can also specify `--password`, `--force` (to overwrite), and `--verbose`:

```bash
python ghostwire.py embed \
  -p payloads/secret.txt \
  -c carriers/audio/track.wav \
  -o output/stego_audio.wav \
  --password "CorrectHorseBatteryStaple123" \
  --force \
  --verbose
```

---

### 3. Extract and Decrypt a Hidden Payload

Recover the hidden file from a stego carrier:

```bash
# Extract to a directory (preserves original filename stored in metadata)
python ghostwire.py extract \
  -c output/stego_landscape.png \
  -o output/recovered/

# Or specify an explicit target filename
python ghostwire.py extract \
  -c output/stego_audio.wav \
  -o output/recovered_document.pdf \
  --password "CorrectHorseBatteryStaple123" \
  --force
```

---

## Capacity Estimation Formulas

| Carrier Type | Raw Capacity Formula | Usable Capacity (Rule of Thumb) |
| :--- | :--- | :--- |
| **PNG Image** | $\text{Width} \times \text{Height} \times 3 \text{ bits}$ | $\approx \frac{\text{Width} \times \text{Height} \times 3}{8} - 150 \text{ bytes}$ |
| **WAV Audio** | $\text{Frames} \times \text{Channels} \text{ bits}$ | $\approx \frac{\text{Frames} \times \text{Channels}}{8} - 150 \text{ bytes}$ |

*Fixed Overhead*:
- Bootstrap Header v2: 24 bytes
- Metadata Envelope: ~50–80 bytes (depends on filename length)
- AES-256-GCM Nonce & Tag: 28 bytes
- PBKDF2 Salt: 16 bytes

---

## Security Model & Steganalysis Resistance

1. **Defense Against Carrier Re-Use**:
   Standard LSB steganography uses a static seed `SHA256(password)`, which embeds bits in the exact same positions regardless of carrier. GhostWire binds positions to an invariant MSB hash of the carrier plus a cryptographically generated 16-byte random salt.
2. **Chi-Square Uniformity**:
   Because the payload is encrypted with AES-256-GCM prior to embedding, the embedded bitstream has maximum entropy ($p \approx 0.5$ for bit 0 vs 1). Combined with PRNG sampling across the entire carrier, modifications are uniformly distributed rather than clustered in top scanlines, defeating naive visual, frequency, and sample-pair steganalysis.
3. **Tamper Proofing**:
   Any modification to the stego carrier (flipping a bit or altering audio samples) will cause either bootstrap header validation to fail or AES-256-GCM authentication tag verification to fail (`InvalidTag`), preventing execution of corrupted or tampered payloads.

---

## Current Limitations

- **Lossless Only**: Carriers must remain lossless. Converting a stego PNG to JPEG or a stego WAV to MP3 destroys the least significant bit plane and renders payloads unrecoverable.
- **Uncompressed PCM Audio**: Only uncompressed PCM WAV files are supported (8-bit, 16-bit, 24-bit, 32-bit). Compressed WAV formats (such as ADPCM) are rejected.
- **Single Carrier**: Payloads cannot currently be split across multiple carriers (planned for v3.0).

---

## Running the Test Suite

GhostWire includes a 64-test automated suite covering cryptography, framing, steganography engines, capacity estimation, steganalysis, and CLI integration.

```bash
pytest -v
```

---

## Disclaimer

GhostWire is designed and intended strictly for educational, research, authorized penetration testing, and defensive cybersecurity purposes. Users are responsible for complying with all applicable local, national, and international laws.

---

## License

MIT License. See [LICENSE](LICENSE) for details.