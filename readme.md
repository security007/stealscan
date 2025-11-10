# 🧠 **StealScan**

### *CLI Scanner for Stealer, Logger, and Malicious Files on Windows*

![Banner](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge) ![Static Badge](https://img.shields.io/badge/Malware_Scanner-CLI-orange?style=for-the-badge) ![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

---

## 🚀 **Overview**

**StealScan** adalah alat **command-line interface (CLI)** untuk mendeteksi file berbahaya seperti:

* 🕵️‍♂️ **Stealer**
* 🎣 **Logger**
* 🦠 **Malicious executables (EXE)**
* 📄 **Office Macros / Scripts**

Scanner ini cocok untuk **analisis keamanan** dan **deteksi malware** secara cepat di Windows (dengan Python).

---

## 🧩 **Fitur Utama**

✅ **Multi-file type scanning** (`.exe`, `.js`, `.vbs`, `.docm`, `.xlsm`, dll)
✅ **Signature-based detection** via custom **rules.json**
✅ **Optional VirusTotal integration** (auto-scan hash/file)
✅ **Recursive directory scan**
✅ **Colored CLI output** 
✅ **Logging hasil scan otomatis** ke file

---

## ⚙️ **Instalasi**

### 1. Clone Repository

```bash
git clone https://github.com/security007/stealscan.git
cd stealscan
```

### 2. Install Dependencies

Pastikan Python versi ≥ 3.9 sudah terpasang.

```bash
pip install -r requirements.txt
```

### 3. Konfigurasi Environment

```env
# Maximum allowed file size (KB)
MAX_SIZE=100000

# Enable or disable VirusTotal scanning
VT_SCAN=false

# (Optional) Your VirusTotal API key
VIRUS_TOTAL_API_KEY=your_api_key_here
```

---

## 🧠 **Cara Penggunaan**
### 📁 Scan Seluruh Folder (Recursive)

```bash
python stealscan.py path/to/folder
```

### 💬 Contoh Output

```bash
[+] Scanning: C:\Users\Admin\Downloads\payload.exe
    [!] Size: 512.24 KB
    [!] Found: Suspicious API Call - CreateRemoteThread
    [!] Found: Keylogger pattern detected
```

Jika aman:

```bash
[+] Scan Results:
    [+] All Clean
```

---

## 🧰 **Struktur Folder**

```
stealscan/
├── analyzers/
│   ├── exe_analyzer.py
│   ├── macro_analyzer.py
│   ├── script_analyzer.py
│   ├── vt_analyzer.py
│   └── rules_loader.py
├── utils/
│   ├── file_loader.py
│   ├── logger.py
│   └── colorize.py
├── .env
├── requirements.txt
└── stealscan.py
```

---

## 🧪 **Contoh Rule (rules.json)**

```json
{
  "stealer_keywords": [
    "discordapp.com/api/webhooks",
    "GetAsyncKeyState",
    "token=[\\\\\"']?[a-z0-9\\-_]{20,}",
    "login\\.microsoftonline\\.com",
    "accounts\\.google\\.com/o/oauth2",
    "userData\\\\Local\\\\Google\\\\Chrome",
    "userData\\\\Roaming\\\\Opera Software",
    "userData\\\\Roaming\\\\Mozilla\\\\Firefox",
    "userData\\\\Roaming\\\\BraveSoftware\\\\Brave-Browser",
    "AppData\\\\Local\\\\BraveSoftware",
    "wallet.dat",
    "WebClient\\.DownloadString",
    "subprocess\\.Popen\\(\\[['\"]cmd",
    "TelegramClient\\(",
    "browser_cookie3",
    "os\\.environ\\[\\\"?USERNAME\\\"?\\]",
    "os\\.getlogin\\(\\)",
    "requests\\.post\\(\\[\\'\\\"]https://.*?",
    "open\\(\\['\\\"]cookies\\.sqlite",
    "open\\(\\['\\\"]key3\\.db",
    "open\\(\\['\\\"]logins\\.json"
  ],
  "keylogger_patterns": [
    "keylog",
    "pynput\\.keyboard",
    "keyboard\\.read_key",
    "SetWindowsHookExA",
    "SendInput",
    "WriteFile",
    "CreateFile\\(",
    "OpenProcess\\(",
    "logging\\.info\\(",
    "win32api\\.GetKeyState",
    "keyboard\\.on_press",
    "InputLogger",
    "GetKeyboardState",
    "GetForegroundWindow",
    "GetWindowTextW"
  ],
  "suspicious_apis": [
    "GetAsyncKeyState",
    "SetWindowsHookExA",
    "WriteFile",
    "CreateFileA",
    "OpenProcess",
    "InternetOpenUrlA",
    "URLDownloadToFileA",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "GetProcAddress",
    "LoadLibraryA",
    "NtQueryInformationProcess"
  ],
  "macro_keywords": [
    "Shell",
    "CreateObject",
    "WScript",
    "AutoOpen",
    "Auto_Close",
    "Execute",
    "Document_Open",
    "FileSystemObject",
    "PowerShell",
    "cmd.exe",
    "base64decode",
    "DownloadString",
    "Kill",
    "Environ\\(",
    "WriteText",
    "GetObject"
  ]
}
```

---

## 🌐 **VirusTotal Integration (Optional)**

Jika `VT_SCAN=true`, maka setiap file akan:

* Dicek hash-nya ke VirusTotal.
* Menampilkan hasil deteksi AV jika terdaftar.

⚠️ Pastikan `VT_API_KEY` di `.env` sudah diisi valid.

---

## 📜 **Output Log**

Hasil scan otomatis disimpan di:

```
logs/scan_results.txt
```

Format:

```
[2025-11-10 20:45:21] payload.exe - [Suspicious API Call: CreateRemoteThread]
```

---

## 🎨 **Tampilan CLI (Contoh)**

```
[+] Scanning: sample.js
    [!] Size: 34.25 KB
    [!] Found: Obfuscated Script - eval(base64decode(...))
[+] Scanning: report.xlsm
    [+] All Clean

[+] Scan Results:
    [+] sample.js
        [!] Obfuscated Script: eval(base64decode(...))
```

---

## 🧤 **Kontribusi**

Ingin bantu mengembangkan? Silakan fork repo ini dan buat pull request:

1. Fork repo ini
2. Buat branch fitur: `git checkout -b fitur-baru`
3. Commit perubahan: `git commit -m "Add fitur baru"`
4. Push: `git push origin fitur-baru`
5. Buat pull request 🧩

---

## 🪪 **Lisensi**

📄 [MIT License](LICENSE)

---

## 💡 **Credits**

* Inspired by forensic & malware analysis tools
* Built with ❤️ using Python
