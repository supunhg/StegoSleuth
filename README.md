# StegoSleuth 🕵️‍♂️

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)

**StegoSleuth** is an automated steganography detection tool designed specifically for CTF (Capture The Flag) challenges. It helps identify and extract hidden data from images using various steganographic techniques commonly encountered in cybersecurity competitions.

## 🚀 Features

- **File Signature Analysis**: Detects mismatched file extensions (e.g., PNG with JPEG header)
- **Metadata Extraction**: Analyzes EXIF data for hidden information
- **LSB Steganography Detection**: Checks for Least Significant Bit hidden data
- **Hidden File Detection**: Uses binwalk to find embedded files
- **String Analysis**: Extracts and analyzes text strings for suspicious content
- **Color Channel Analysis**: Identifies anomalies in RGB channels
- **Manual & Automatic Modes**: Run specific checks or comprehensive analysis
- **Colorized Output**: Easy-to-read results with color-coded findings
- **Export Results**: Save analysis results to file

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Quick Install

1. **Clone the repository:**
   ```bash
   git clone https://github.com/supunhg/StegoSleuth.git
   cd StegoSleuth
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install binwalk (optional but recommended):**
   
   **Windows:**
   ```bash
   # Using chocolatey
   choco install binwalk   
   ```
   
   **Linux (Ubuntu/Debian):**
   ```bash
   sudo apt-get install binwalk
   ```
   
   **macOS:**
   ```bash
   brew install binwalk
   ```

## 📖 Usage

### Basic Usage

Run comprehensive analysis on an image:
```bash
python stegosleuth.py image.png
```

### Advanced Usage

**Run specific checks:**
```bash
# Check file signature only
python stegosleuth.py image.png --check signature

# Check for LSB steganography
python stegosleuth.py image.png --check lsb

# Check metadata
python stegosleuth.py image.png --check metadata
```

**Available check types:**
- `signature` - File signature vs extension mismatch
- `metadata` - EXIF metadata analysis  
- `lsb` - LSB steganography detection
- `hidden` - Hidden/embedded files (requires binwalk)
- `strings` - String extraction and analysis
- `colors` - Color channel anomaly detection

**Verbose output:**
```bash
python stegosleuth.py image.png --verbose
```

**Save results to file:**
```bash
python stegosleuth.py image.png --output results.txt
```

**Combine options:**
```bash
python stegosleuth.py image.png --check lsb --verbose --output lsb_results.txt
```

## 🖼️ Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║                        StegoSleuth v1.0                      ║
║              Automated Steganography Detection               ║
╚═══════════════════════════════════════════════════════════════╝

Running all checks...
FOUND: File Signature Check: File has .png extension but is actually JPEG
FOUND: Metadata Analysis: Comment: flag{hidden_in_metadata}
FOUND: LSB Steganography: Possible hidden text: The secret message is...
INFO: Hidden Files Check: Found 1 embedded files: ZIP archive data
INFO: String Analysis: Found 2 suspicious strings: flag, secret_key
INFO: Color Analysis: No color channel anomalies detected

═══ ANALYSIS SUMMARY ═══
Total checks: 6
Passed: 2
Findings: 4
Errors: 0

🎯 POTENTIAL STEGANOGRAPHY DETECTED!
Review the findings above for hidden data.
```

## 🔍 Detection Methods

### 1. File Signature Analysis
Checks if the file's actual format matches its extension. Common CTF trick is renaming file types.

### 2. Metadata Extraction
Analyzes EXIF data and other metadata fields for:
- Suspicious keywords (flag, ctf, hidden, secret, password)
- Unusual comments or descriptions
- Custom metadata fields

### 3. LSB Steganography
Examines the least significant bits of pixel values to detect hidden text or data patterns.

### 4. Hidden File Detection
Uses binwalk to identify:
- Embedded ZIP/RAR archives
- Hidden executables
- Nested images
- Other file formats

### 5. String Analysis
Extracts printable ASCII strings and searches for:
- Flag formats
- Suspicious keywords
- Base64 encoded data
- Cipher text patterns

### 6. Color Channel Analysis
Analyzes RGB channels for:
- Unusual statistical patterns
- Low variation indicators
- Channel-specific anomalies

## 🎯 CTF Use Cases

**Common scenarios where StegoSleuth helps:**

1. **File Extension Tricks**: Image appears as PNG but is actually JPEG
2. **Metadata Flags**: Hidden flags in EXIF comments or descriptions
3. **LSB Hiding**: Text hidden in least significant bits of pixels
4. **Embedded Files**: ZIP files or other data hidden within images
5. **String Extraction**: Readable text hidden in binary data
6. **Multi-layer Steganography**: Combination of multiple techniques

## 🔧 Configuration

### Custom Keywords
Edit the `keywords` list in `stegosleuth.py` to add custom search terms:
```python
keywords = ['flag', 'ctf', 'password', 'secret', 'hidden', 'key', 'base64', 'cipher', 'custom_term']
```

### Sensitivity Settings
Adjust detection thresholds in the respective check functions:
- LSB detection sensitivity
- String length minimums
- Color channel variation thresholds

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- New steganography detection methods
- Performance improvements
- Bug fixes
- Documentation improvements
- Additional output formats

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **binwalk** - For embedded file detection
- **Pillow & OpenCV** - For image processing
- **exifread** - For metadata extraction
- **python-magic** - For file type detection
- **Click** - For CLI interface

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/supunhg/StegoSleuth/issues) page
2. Create a new issue with:
   - Your operating system
   - Python version
   - Error messages
   - Sample image (if possible)

---

**Happy CTF hunting! 🏁**
