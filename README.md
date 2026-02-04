# 🔐 PDF Malware Analyzer

<div align="center">

[![Python Version](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Mac%20|%20Linux-green?style=for-the-badge)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)](https://github.com/)

**A powerful, automated Python toolkit for analyzing PDF files to detect malicious content, embedded exploits, and security threats.**

</div>

---

## 📌 Table of Contents

- [About](#about)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Output & Reports](#output--reports)
- [Risk Scoring](#risk-scoring)
- [Export as EXE](#export-as-exe)
- [Tools & Technologies](#tools--technologies)
- [Use Cases](#use-cases)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## 📖 About

PDF Malware Analyzer is a **static analysis toolkit** built in Python that inspects PDF files for malicious indicators without executing any content. It is designed for **SOC analysts, security researchers, students, and blue team professionals**.

Attackers frequently weaponize PDF documents for phishing, malware delivery, and exploit attacks. This tool helps defenders quickly identify and assess the threat level of any PDF file.

---

## ✅ Features

| Feature | Description |
|---|---|
| 📂 Metadata Extraction | Extracts author, dates, creator, and detects anomalies |
| 🔍 Object Enumeration | Scans PDF structure for suspicious objects and keywords |
| ⚡ JavaScript Detection | Finds embedded JS, obfuscation, and suspicious functions |
| 🌐 IOC Extraction | Extracts URLs, IPs, emails, domains, and file hashes |
| 📊 Risk Scoring | Automated scoring system (0-100) with severity levels |
| 📄 Report Generation | Generates detailed security analysis reports |
| 🚀 Automated Pipeline | One-command full analysis from start to report |

---

## 📁 Project Structure

```
PDF_Malware_Analyzer/
│
├── main.py                          # Main entry point
├── setup.py                         # Package setup (pip install)
├── build.py                         # Build EXE script
├── requirements.txt                 # Python dependencies
├── .gitignore                       # Git ignore rules
├── README.md                        # This file
│
├── analyzers/                       # Core analysis modules
│   ├── __init__.py
│   ├── metadata_analyzer.py         # Metadata extraction & checks
│   ├── object_analyzer.py           # PDF object enumeration
│   ├── javascript_analyzer.py       # JS detection & analysis
│   ├── ioc_extractor.py            # IOC extraction (URLs, IPs, etc.)
│   └── risk_scorer.py              # Risk calculation engine
│
├── utils/                           # Utility functions
│   ├── __init__.py
│   ├── pdf_parser.py               # Reusable PDF parsing helpers
│   └── report_generator.py         # Report creation
│
├── config/                          # Configuration & indicators
│   ├── __init__.py
│   └── indicators.py               # Keywords, patterns, weights
│
├── samples/                         # Place test PDFs here
└── reports/                         # Generated reports saved here
```

---

## 💻 Installation

### Option 1: Clone from GitHub (For Developers)

```bash
# 1. Clone the repository
git clone https://github.com/YOUR-GITHUB-USERNAME/PDF-Malware-Analyzer.git

# 2. Go into the folder
cd PDF-Malware-Analyzer

# 3. Install dependencies
pip install -r requirements.txt
```

### Option 2: Install as a Package

```bash
# Install in development mode
pip install -e .

# Now you can use it as a command anywhere:
pdf-analyzer your-file.pdf
```

### Option 3: Download EXE (For Normal Users)

> Download the pre-built `.exe` from the **Releases** tab on GitHub.
> No Python installation needed!

---

## 🚀 Usage

### Basic Command

```bash
python main.py <path_to_pdf>
```

### Examples

```bash
# Analyze a PDF in samples folder
python main.py samples/test.pdf

# Analyze a PDF from any location
python main.py C:/Documents/invoice.pdf

# If installed as package
pdf-analyzer samples/test.pdf
```

---

## ⚙️ How It Works

The tool follows a **7-step automated pipeline**:

```
START
  ↓
[1] Load PDF File          →  Read file + extract metadata
  ↓
[2] Object Enumeration     →  Identify all PDF objects
  ↓
[3] Keyword Scanning       →  Search for /JavaScript, /OpenAction, etc.
  ↓
[4] Deep Parsing           →  Extract JS code, streams, compressed data
  ↓
[5] IOC Extraction         →  Find URLs, IPs, emails, hashes
  ↓
[6] Risk Scoring           →  Calculate threat score (0-100)
  ↓
[7] Report Generation      →  Save detailed analysis report
  ↓
END
```

---

## 📊 Output & Reports

### Console Output
- Real-time colored progress updates
- Summary of findings at the end

### Generated Report Includes
- ✅ Executive Summary with verdict
- ✅ Metadata Analysis
- ✅ Object & Keyword Analysis
- ✅ JavaScript Findings
- ✅ Full IOC List (URLs, IPs, Emails, Hashes)
- ✅ Risk Assessment
- ✅ Mitigation Recommendations

Reports are saved automatically in the `reports/` folder.

---

## 📈 Risk Scoring

| Score | Severity | Meaning |
|---|---|---|
| 0 - 30 | 🟢 LOW | File appears safe |
| 31 - 50 | 🟡 MEDIUM | Some suspicious indicators |
| 51 - 75 | 🟠 HIGH | Multiple threats detected |
| 76 - 100 | 🔴 CRITICAL | Highly malicious — quarantine immediately |

### Scoring Weights

| Indicator | Weight |
|---|---|
| JavaScript Found | +20 |
| Auto-Action Detected | +25 |
| Embedded File | +15 |
| Code Obfuscation | +20 |
| URLs Found | +10 |
| Exploit Pattern | +30 |
| Suspicious Metadata | +5 |
| Encoded Streams | +10 |

---

## 📦 Export as EXE

To create a standalone `.exe` for Windows users:

```bash
# 1. Install PyInstaller
pip install pyinstaller

# 2. Run the build script
python build.py

# 3. Find the EXE in:
dist/PDF_Malware_Analyzer.exe
```

---

## 🛠️ Tools & Technologies

| Tool / Library | Purpose |
|---|---|
| Python 3.7+ | Core language |
| PyPDF2 | PDF reading & parsing |
| pdfminer.six | Advanced PDF text extraction |
| validators | URL & domain validation |
| colorama | Colored terminal output |
| PyInstaller | Build standalone EXE |

---

## 🎯 Use Cases

- **SOC Analysts** — Quickly triage incoming PDF attachments
- **Incident Responders** — Analyze suspicious PDFs during investigations
- **Students** — Learn how PDF malware works and how to detect it
- **Blue Teams** — Add to email filtering and security pipelines
- **Penetration Testers** — Understand PDF attack vectors

---

## 🤝 Contributing

Want to improve this project? Here's how:

1. **Fork** the repository
2. **Create** a new branch: `git checkout -b feature-your-feature`
3. **Make** your changes
4. **Commit**: `git commit -m "Added new feature"`
5. **Push**: `git push origin feature-your-feature`
6. **Open** a Pull Request

### Ideas for Contributions
- Add new detection rules
- Improve risk scoring accuracy
- Add GUI interface
- Add more IOC extraction types
- Add VirusTotal API integration

---

## 📝 Learning Outcomes

By using or contributing to this project, you learn:

- How PDF malware works internally
- How attackers hide payloads inside documents
- Static malware analysis techniques
- Threat intelligence and IOC extraction
- Security report writing (SOC/IR style)
- Python packaging and tool development

---

## ⚠️ Disclaimer

> This tool is for **educational and authorized security research purposes only**.
>
> - Only analyze files you have **permission** to analyze
> - Do **not** use for any illegal or malicious activity
> - Always work in **isolated environments** when testing with real malware samples
> - The authors are **not responsible** for any misuse

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

| Name | Role |
|---|---|
| Your Name | Developer & Creator |

---

<div align="center">

⭐ **If you find this useful, please star the repository!** ⭐

</div>
