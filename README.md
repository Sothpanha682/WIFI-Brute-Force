# WifiBF — WiFi Security Testing & Brute Force Tool

A fast, lightweight, and modern graphical tool written in **Rust** using **egui** / **eframe** and native **Windows WLAN APIs (`Wlanapi.dll`)** to audit and test WPA2-Personal (WPA2-PSK) wireless networks against wordlists.

> ⚠️ **Disclaimer / Educational Purpose Only:**
> This tool is intended strictly for educational purposes, authorized security testing, and network auditing on networks you own or have explicit permission to test. Unauthorized access to computer networks is illegal.

---

## ✨ Features

- **Native Windows WLAN API**: Interacts directly with Windows Native Wifi (`wlanapi.dll`) without requiring external dependencies like Python, Netsh CLI wrappers, or Scapy.
- **Modern Dark UI**: Clean, responsive desktop interface built with **egui** and **eframe**.
- **Real-time WiFi Scanner**:
  - Scans nearby 2.4 GHz and 5 GHz networks.
  - Live signal strength indicator and quality breakdown.
  - Security status and one-click target SSID selection.
- **Wordlist Attack Runner**:
  - Line-by-line dictionary testing.
  - Live attempt logs and instant visual status badges.
  - Real-time **Stop / Abort** control via atomic cancellation flags.
  - File picker (`rfd`) to select custom wordlists easily.

---

## 📋 Requirements

- **Operating System**: Windows 10 / 11 (64-bit)
- **Privileges**: **Administrator privileges** (required by Windows Native Wifi API to create profiles and associate interfaces)
- **Hardware**: Compatible WiFi / WLAN Network Adapter (internal or USB dongle)
- **Build Toolchain**: [Rust & Cargo](https://rustup.rs/) (edition 2021+)

---

## 🚀 Installation & Build

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Sothpanha682/WIFI-Brute-Force.git
   cd WIFI-Brute-Force
   ```

2. **Build Release Binary:**
   ```bash
   cargo build --release
   ```
   The compiled executable will be located at:
   ```text
   target/release/wifibf.exe
   ```

---

## 🖥️ Usage

1. **Run as Administrator:**
   Right-click the executable (`wifibf.exe`) or your terminal and select **Run as Administrator**.
   
2. **Scan for Networks:**
   - Click **"Scan Networks"** in the sidebar.
   - Select your target SSID from the scanned list (or manually enter the SSID).

3. **Select Wordlist:**
   - Click **"Browse..."** to choose a `.txt` wordlist file (a starter [words.txt](words.txt) is included).

4. **Start Attack:**
   - Click **"Start Attack"**.
   - Monitor connection attempts and results in real time.
   - Click **"Stop"** at any moment to abort testing.

---

## ⚙️ Configuration & Delays

All connection delay parameters can be inspected or adjusted in [`src/wifi.rs`](src/wifi.rs):
- **Per-Attempt Connection Wait**: `350 ms` (wait time for Windows WLAN service to associate and verify connection status before querying).
- **Network Scan Delay**: `2 s` (active/passive sweep duration).
- **Post-Success Delay**: `3 s` (cooldown after successful handshake).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
