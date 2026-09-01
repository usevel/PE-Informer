# 🔍 PE Informer

![C++](https://img.shields.io/badge/Language-C%2B%2B20-blue.svg?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20(x86%20%2F%20x64)-0078d7.svg?style=flat-square)
![Graphics](https://img.shields.io/badge/Graphics-DirectX%2011-purple.svg?style=flat-square)
![UI](https://img.shields.io/badge/GUI-Dear%20ImGui-orange.svg?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)

A lightweight, standalone, and high-performance **Portable Executable (PE)** static analysis tool built with modern **C++20**, **DirectX 11**, and **Dear ImGui**.

Designed for malware analysts, reverse engineers, and system developers to quickly inspect binary structures, decode undocumented metadata, calculate cryptographic entropy, and detect packers without heavy external dependencies.

---

## 📸 Screenshots
<p><img src="https://i.imgur.com/df8Ekba.png" alt="PE Informer UI" width="500"/></p>

---

## ✨ Key Features

### 🧩 1. Deep PE Header Parsing
* Complete inspection of **DOS Header**, **NT Headers**, **File Header**, and **Optional Header** (supports both **PE32** and **PE32+** architectures).
* Displays critical offsets in real time: `AddressOfEntryPoint` (AEP), `BaseOfCode`, `ImageBase`, `SectionAlignment`, and Subsystem flags (`GUI`, `CONSOLE`, `SYS/Native`, `DLL`).

### 🔑 2. Undocumented Rich Header Decoding
* Automated backwards search for `Rich` (`0x68636952`) and `DanS` (`0x536e6144`) magic signatures.
* Extracts the 4-byte **XOR Key** and decrypts embedded compiler/linker metadata.
* Identifies exact toolchain versions, MSVC build numbers (`Product ID`), and linker configurations.

### 📊 3. Shannon Entropy Calculation & Visualization
* Calculates mathematical Shannon Entropy:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* **Global & Per-Section Analysis:** Calculates entropy for each individual section (`.text`, `.data`, `.rsrc`, etc.) to pinpoint packed or encrypted payloads.
* **Cached Execution:** Fast calculation with internal caching (`std::unordered_map`) to maintain high UI framerates without lagging.

### 🛡️ 4. Heuristic Packer & Protector Detection
* Signature and name-based heuristic detection for common packers and crypters:
  * **UPX**, **VMProtect**, **Themida**, **WinLicense**, **ASPack**, **MPRESS**, **Enigma Protector**.
* **Anomaly Detection:** Flags binaries missing standard execution sections (e.g., missing `.text`) or containing sections with suspicious entropy thresholds ($H > 7.4$).

### 🎨 5. Modern & Minimalist UI
* Hardware-accelerated rendering powered by **DirectX 11** and **Dear ImGui**.
* **Native Windows DWM Dark Mode:** Uses `DwmSetWindowAttribute` for seamless integration with the OS dark theme.
* **Drag-and-Drop:** Instant file inspection via native Win32 `WM_DROPFILES` support.

---

## 🛠️ Tech Stack & Architecture

* **Language:** Modern C++ (C++20 standard)
* **GUI / Graphics:** Dear ImGui, DirectX 11 SDK
* **Windows APIs:** WinAPI, DWM API (`dwmapi.lib`), Shell API
* **Algorithms:** Shannon Entropy formula, Binary Parsing, Heuristic Pattern Matching

---

## 🚀 How to Build

### Prerequisites
* **OS:** Windows 10 / 11 (x64)
* **IDE:** Visual Studio 2022 (v143 toolset) or newer
* **Dependencies:** Windows 10/11 SDK (DirectX 11 is included by default)

### Build Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/usevel/PE-Informer.git
   cd PE-Informer
   ```
2. Open `PE-Informer.sln` in **Visual Studio**.
3. Select **Release** configuration and **x64** (or **x86**) platform.
4. Build the solution (`Ctrl + Shift + B`).
5. The compiled executable will be available in the `bin/Release/` directory.

---

## 🎯 Usage
1. Launch `PE-Informer.exe`.
2. **Drag and drop** any `.exe`, `.dll`, or `.sys` file into the application window.
3. *Or* click the folder button (`📁`) to open the file selection dialog.
4. View architectural properties, linker history, entropy scores, and section details immediately.

---

## 📜 License
This project is licensed under the **MIT License** — feel free to use and modify it for educational, personal, or commercial purposes.
