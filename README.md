# Chimera
chimera is a program that injects itself into a Linux ELF program by overwriting the PT_NOTE section of the target ELF file thereby enabling the hacker run malicious code. This malicious code could be a backdoor!

## Features
- Overwrites **PT_NOTE** to insert a new section
- Maintains ELF structure integrity
- Supports **x86_64 Linux ELF binaries**
- Injects payloads dynamically

## How It Works
1. **Parses the ELF file**
2. **Finds and modifies the PT_NOTE segment**
3. **Injects a new section with custom payload**
4. **Ensures the ELF remains executable**

## Installation
### 🔧 Dependencies
- Linux OS
- `gcc` (or `clang`)
- `make`

### 📦 Build
```sh
git clone https://github.com/hotwrist/chimera.git
cd chimera
make
```

## Usage
### 💎 Injecting a Payload
```sh
./chimera <target.elf> <payload.bin> ".inject_section" <injected_session_address> <entry point>
```

## Example
```sh
./chimera date backdoor.bin ".chimera" 0x600000 -1
./date
```

## 🛡️ Legal Disclaimer
This tool is intended for educational and research purposes **only**. **Do not** use it on unauthorized systems.

## 🌟 License
This project is licensed under the **MIT License**. See `LICENSE` for details.


