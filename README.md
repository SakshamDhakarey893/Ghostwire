# GhostWire

> Hide. Encrypt. Transmit. Undetected.

GhostWire is a Python-based steganography framework designed to securely conceal encrypted payloads inside digital media. The project combines randomized LSB steganography, strong encryption, integrity verification, and payload compression to create a professional-grade cybersecurity tool.

---

## Features

### Current Features

- PNG image steganography (RGB / RGBA)
- WAV audio steganography (uncompressed PCM audio)
- Randomized LSB embedding across pixel channels & audio samples
- Password-protected payloads
- AES-256-GCM authenticated encryption
- PBKDF2 key derivation (600,000 iterations)
- SHA-256 integrity verification
- Payload compression using zlib
- Full arbitrary file embedding support
- Unified Command-line interface (CLI)

### Planned

- Logging and live progress tracking (tqdm / colorama)
- Video steganography
- Multi-carrier payload splitting
- Steganalysis module
- Modern Desktop GUI application

### Planned (v3.0)

- Video steganography
- Multi-carrier payload splitting
- Steganalysis module
- GUI interface

---

## Architecture

Payload
↓
Compression (zlib)
↓
Encryption (AES-256-GCM)
↓
Metadata Packaging
↓
Binary Encoding
↓
Randomized Pixel Selection
↓
LSB Embedding
↓
Stego Image

---

## Project Structure

```text
ghostwire/

├── ghostwire.py
│
├── core/
│   ├── image_stego.py
│   ├── audio_stego.py
│   ├── crypto.py
│   ├── compression.py
│   ├── integrity.py
│   ├── randomizer.py
│   ├── metadata.py
│   └── utils.py
│
├── carriers/
│   ├── images/
│   └── audio/
│
├── payloads/
│
├── output/
│
├── tests/
│
├── requirements.txt
│
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/SakshamDhakarey893/Ghostwire.git
cd Ghostwire
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

### Windows

```bash
venv\Scripts\activate
```

### Linux

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Security Design

### Randomized LSB Embedding

Instead of embedding data sequentially into pixels, GhostWire uses password-derived random pixel positions.

Benefits:

- Harder to detect
- Harder to extract without password
- Better resistance against simple steganalysis

### Encryption

GhostWire encrypts payloads before embedding.

Algorithm:

- AES-256-GCM

### Integrity Verification

Every payload includes a SHA256 hash for verification during extraction.

---

## Roadmap

### Sprint 1

- Project setup
- Module skeletons
- Git initialization
- Documentation

### Sprint 2

- Randomized LSB embedding engine

### Sprint 3

- Extraction engine

### Sprint 4

- Encryption integration

### Sprint 5

- Compression integration

### Sprint 6

- CLI implementation

### Sprint 7

- Testing and optimization

---

## Disclaimer

GhostWire is intended for educational, research, and defensive cybersecurity purposes only.

Users are responsible for complying with all applicable laws and regulations.

---

## License

MIT License