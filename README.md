# Wenle Antivirus 

Wenle Rust Editions is a Rust-based Windows antivirus system with real-time monitoring, YARA scanning, memory analysis and file integrity checking. This project is open source and welcomes reference, modification, and extension.

## 🔍 Features

- 🧠 Process Monitoring: Detects and terminates malicious processes
- 🧬 Memory Scanning: Analyzes abnormal process memory behavior
- 📁 File Monitoring: Monitors file additions and modifications for immediate threat isolation
- 🧹 Junk Cleaner: Cleans system junk and temporary files
- 🧰 GUI: Uses egui to provide a simple user interface

## 🛡️ Security
I can promise Wenle is not a malware. Windows defender or other antivirus software might falsely flag this antivirus program, but after VirusTotal scan, it's safe; only a few antivirus programs gave it a false positive.

## ⚙️ Compile



`
cargo build --release
`
## How to use Wenle?
You should first place the compiled files in the "Configuration" folder, then unzip "anti.zip" and Wenle should work normally.


