# 🔒 Zerotrace – Secure Wipe CLI Tool

**Zerotrace** is a cross-platform **secure data wiping CLI tool** written in Python.  
It can wipe **files, folders, or entire disks/SSDs** using strong erase methods.  

⚠️ **Warning:** Wiping is **permanent**. Use at your own risk.

---

## ✨ Features
- Detects connected storage devices (Windows, Linux, macOS).
- Wipe methods:
  - **Zero-fill (NIST 800-88)** – overwrite with `0x00`
  - **DoD 3-pass (5220.22-M)** – Zero → Ones → Random
  - **CryptoErase (AES-256)** – encrypt with random key & destroy key
- File and folder secure delete
- Whole disk/SSD wiping option
- Interactive CLI with error handling
- Cross-platform support

---

## 📦 Installation
Clone the repo and install dependencies:

```bash
git clone https://github.com/Hemachandran006 /zerotrace.git
cd zerotrace
python zerotrace.py
