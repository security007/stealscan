# StealScan - Malware Scanner

### *Scanner for Stealer, Logger, and Malicious Files*

![Banner](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge) ![Static Badge](https://img.shields.io/badge/Malware_Scanner-CLI-orange?style=for-the-badge) ![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

---

## 🚀 New Features

### Universal File Support
StealScan now scans **ALL file types** including:

- **Scripts**: `.py`, `.js`, `.vbs`, `.bat`, `.ps1`, `.sh`, `.php`, `.pl`, `.rb`, `.lua`
- **Office Documents**: `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.odt`
- **Executables**: `.exe`, `.dll`, `.sys`, `.scr`, `.com`, `.msi`
- **Archives**: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.bz2`, `.cab`
- **PDFs**: Extracts and scans text, detects JavaScript
- **Images**: Scans metadata for suspicious content
- **Android**: `.apk`, `.dex`, `.jar` files
- **Configuration**: `.ini`, `.cfg`, `.json`, `.xml`, `.yaml`
- **Web Files**: `.html`, `.htm`, `.css`, `.asp`, `.jsp`
- **Databases**: `.db`, `.sqlite`, `.mdb`
- **Binary Files**: Extracts strings and scans content

### Intelligent Scanning
- **Magic byte detection** for accurate file type identification
- **String extraction** from binary files
- **Archive content analysis** without extraction
- **Metadata scanning** for images and documents
- **Context-aware detection** shows surrounding code

## 📦 Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install System Dependencies (Optional)

**For Windows:**
```bash
# python-magic-bin is included in requirements.txt
```

**For Linux:**
```bash
sudo apt-get install libmagic1
```

**For macOS:**
```bash
brew install libmagic
```

### 3. Install RAR Support (Optional)

**Windows:**
- Download WinRAR from https://www.rarlab.com/
- Add to PATH: `C:\Program Files\WinRAR`

**Linux:**
```bash
sudo apt-get install unrar
```

**macOS:**
```bash
brew install unrar
```

## 🎯 Usage

### Basic Usage

**Scan a single file:**
```bash
python stealscan.py suspicious_file.exe
```

**Scan a directory (recursive):**
```bash
python stealscan.py /path/to/folder
```

### Advanced Options

**Verbose mode** (show details for each file):
```bash
python stealscan.py -v /path/to/folder
```

**Non-recursive scan** (don't scan subdirectories):
```bash
python stealscan.py -nr /path/to/folder
```

**Quiet mode** (only show threats):
```bash
python stealscan.py -q /path/to/folder
```

**Combine options:**
```bash
python stealscan.py -v -nr /path/to/folder
```

### Examples

**Scan all downloads:**
```bash
python stealscan.py -v C:\Users\YourName\Downloads
```

**Quick scan without subdirectories:**
```bash
python stealscan.py -nr -q ~/Desktop
```

**Deep scan with VirusTotal:**
```bash
# First, enable VT in .env
python stealscan.py -v /path/to/suspicious/files
```

## ⚙️ Configuration

Edit `.env` file:

```bash
# Maximum file size to scan (in KB)
MAX_SIZE=100000

# Enable VirusTotal scanning
VT_SCAN=false

# VirusTotal API key (get from https://www.virustotal.com/)
VIRUS_TOTAL_API_KEY=your_api_key_here
```

## 📊 Output

### Scan Summary
```
==============================================================
SCAN SUMMARY
==============================================================
Total Files Found:    150
Files Scanned:        145
Infected Files:       3
Errors:               2
Skipped (too large):  3
==============================================================
```

### Detection Report
```
[!] THREATS DETECTED IN 3 FILE(S):
==============================================================

[!] C:\suspicious\stealer.py [script]
    [stealer_keywords] 15 detection(s)
      1. discordapp.com/api/webhooks | Context: ...url = "https://discord...
      2. requests.post | Context: ...requests.post(webhook_url, json=data)...
      ... and 13 more
    [keylogger_patterns] 3 detection(s)
      1. pynput.keyboard | Context: ...from pynput.keyboard import Listener...
```

### Log File

All results are saved to `scan_log.txt`:
```
2025-11-17 14:30:45.123456 - C:\test\malware.exe [exe]
  [+] DETECTED: suspicious_api - CreateRemoteThread
  [+] DETECTED: stealer_keywords - discord.com/api/webhooks
```

## 🔍 How It Works

### 1. File Type Detection
- Checks file extension
- Reads magic bytes (file signature)
- Falls back to MIME type detection

### 2. Type-Specific Analysis
- **Scripts/Text**: Regex pattern matching
- **Office Docs**: Macro extraction and analysis
- **Executables**: PE header parsing, imported APIs
- **Archives**: Lists contents, checks for suspicious files
- **PDFs**: Text extraction, JavaScript detection
- **Images**: EXIF metadata analysis
- **Binaries**: String extraction and pattern matching

### 3. Universal Scanning
- All files undergo universal pattern matching
- Extracts context around detections
- Deduplicates results

### 4. VirusTotal Integration (Optional)
- Uploads SHA-256 hash
- Retrieves scan results from 70+ antivirus engines

## 🛡️ Detection Categories

### Stealer Indicators
- Discord/Telegram webhooks
- Browser data paths (cookies, passwords)
- Cryptocurrency wallet paths
- OAuth tokens and API keys
- Data exfiltration patterns

### Keylogger Indicators
- Keyboard hooks (SetWindowsHookEx)
- Key state functions (GetAsyncKeyState)
- Input capture libraries (pynput, keyboard)
- Window title monitoring

### Suspicious APIs (PE files)
- Process injection (CreateRemoteThread)
- Memory manipulation (VirtualAlloc, WriteProcessMemory)
- Privilege escalation (AdjustTokenPrivileges)
- Network communications
- Code execution (WinExec, ShellExecute)

### Macro Indicators
- Auto-execution (AutoOpen, Document_Open)
- Shell commands
- PowerShell execution
- File operations
- Registry modifications

## 📝 Tips

1. **Start with verbose mode** to see what's being scanned
2. **Use quiet mode** for quick checks in large directories
3. **Enable VirusTotal** for additional validation (requires API key)
4. **Check scan_log.txt** for complete history
5. **Update rules regularly** in `analyzers/rules/strings.json`

## ⚠️ Limitations

- Large files (>MAX_SIZE) are skipped
- Encrypted archives cannot be scanned
- Some file types require optional dependencies
- Binary string extraction may miss obfuscated content
- False positives are possible with legitimate software

## 🔧 Troubleshooting

### "No module named 'magic'"
```bash
pip install python-magic python-magic-bin
```

### "Failed to load libmagic"
- **Windows**: Install `python-magic-bin`
- **Linux**: `sudo apt-get install libmagic1`
- **macOS**: `brew install libmagic`

### "Cannot open RAR files"
Install UnRAR:
- **Windows**: Install WinRAR and add to PATH
- **Linux**: `sudo apt-get install unrar`
- **macOS**: `brew install unrar`

### VirusTotal errors
- Check API key in `.env`
- Verify VT_SCAN=true
- Ensure internet connection
- Check API rate limits (4 requests/minute for free tier)

## 🚀 Performance

- **Fast scanning**: ~100-200 files per second (text files)
- **Memory efficient**: Streams large files
- **Parallel processing**: Can be enhanced with threading
- **Smart caching**: Skips rescanning unchanged files

## 📄 License

MIT License - Feel free to use, modify, and distribute

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add detection rules to `strings.json`
4. Test thoroughly
5. Submit pull request

## 📧 Support

For issues, questions, or suggestions:
- Check existing issues
- Create new issue with details
- Include sample files (if safe)