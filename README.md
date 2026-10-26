# Assembly_PortScanner

![Language](https://img.shields.io/badge/language-Assembly-blue)
![Platform](https://img.shields.io/badge/platform-Linux%2064--bit-orange)

## Description

A lightweight port scanner implementation written in x86-64 assembly language for Linux. This project demonstrates low-level network programming concepts by creating a tool that can scan open ports on a target IP address.

## Features

- Scans for open ports on a specified IPv4 address
- Written in pure x86-64 assembly (nasm syntax)
- Minimal dependencies — no high-level language runtime required
- Direct system calls for network operations

## Tech Stack

- **Language:** x86-64 Assembly (nasm)
- **Platform:** Linux 64-bit
- **Assembler:** NASM (Netwide Assembler)
- **Linker:** GNU ld

## Prerequisites

Before compiling and running this port scanner, ensure you have:

- **NASM assembler** — for compiling assembly code
- **GNU binutils** (ld linker) — for linking object files
- **Linux 64-bit system** — required for x86-64 architecture
- **Basic network access** — to perform port scans

Install on Ubuntu/Debian:
```bash
sudo apt-get install nasm binutils
```

Install on Fedora/RHEL:
```bash
sudo dnf install nasm binutils
```

## Getting Started

### Compilation

1. **Assemble the source code:**
   ```bash
   nasm -f elf64 asmSyn.asm -o port_scanner.o
   ```

2. **Link the object file:**
   ```bash
   ld port_scanner.o -o port_scanner
   ```

3. **Verify the executable was created:**
   ```bash
   ls -la port_scanner
   ```

## Usage

Run the port scanner:

```bash
./port_scanner
```

### Example

```bash
./port_scanner
IP:
start port:
end port:
```

The scanner will attempt to connect to ports on the specified IP address and report which ports are open or closed.

### Note

- Requires root/sudo privileges for raw socket operations on most Linux systems
- Run with `sudo` if needed:
  ```bash
  sudo ./port_scanner
  ```

## Project Structure

```
Assembly_PortScanner/
├── asmSyn.asm    # Main assembly source code
└── README.md           # Project documentation
```

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

## License

This project is unlicensed. See the repository for more details.

---

<p align="center">
  </a>
</p>
