# Port Scanner (NASM x64 / Windows)

A TCP port scanner written in x64 assembly for Windows, built on Winsock.

- Non-blocking TCP connect scan (up to 64 simultaneous connections)
- Service banner grabbing (with an HTTP probe on common HTTP ports)
- OS guess based on the banner
- Final summary with open ports, ports tested, and timeouts

> **Responsible use:** only scan machines and networks that you own or have
> explicit authorization to test.

---

## Requirements

- Windows 10 (version 2004 or later) or Windows 11, 64-bit
- About 1 GB of free disk space for MSYS2 and the toolchain
- The `port_scanner.asm` file (and this README) in a local folder

> On Windows versions older than 10 2004, `WSAPoll` does not report refused
> connections; those ports show up as `timeout` instead of `closed`.

---

## 1. Install MSYS2

1. Download the installer from <https://www.msys2.org> (file `msys2-x86_64-XXXXXXXX.exe`).
2. Run the installer and keep the default folder: `C:\msys64`.
3. At the end, leave **Run MSYS2 now** checked (or open it from the Start menu).

### Update MSYS2

In the terminal that opens, run:

```bash
pacman -Syu
```

If it asks you to close the terminal, close it, open it again, and run:

```bash
pacman -Su
```

---

## 2. Install the compiler and assembler

Open the **MSYS2 MINGW64** terminal (Start menu → *MSYS2 MINGW64*).

> Do not use *MSYS2 MSYS* or *UCRT64*: this project is built with the MINGW64 toolchain.

```bash
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-nasm
```

Answer `Y` when prompted with `Proceed with installation? [Y/n]`.

Verify the installation:

```bash
gcc -dumpmachine     # should print: x86_64-w64-mingw32
nasm -v              # should print the NASM version
```

---

## 3. Build

In the same **MSYS2 MINGW64** terminal, go to the folder containing `port_scanner.asm`.
The `C:` drive appears as `/c`:

```bash
cd /c/Users/YOUR_USERNAME/Downloads
```

Assemble and link:

```bash
nasm -f win64 port_scanner.asm -o port_scanner.obj
gcc -nostdlib -o port_scanner.exe port_scanner.obj -lws2_32 -lkernel32 -Wl,-e,_start
```

If everything worked, the folder now contains `port_scanner.exe`.

---

## 4. Run

```bash
./port_scanner.exe
```

Or, from PowerShell/CMD, inside the folder:

```powershell
.\port_scanner.exe
```

Always run it from a terminal. If you double-click the file, the window closes as
soon as the program finishes and you won't see the results.

### Example

```
Enter target IPv4 (e.g., 192.168.1.1): 127.0.0.1
Enter start port (1-65535): 1
Enter end port (1-65535): 1024
Scanning 127.0.0.1 ports 1 through 1024
[-] 1 closed/filtered
...
[+] 22 OPEN
    banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
    os guess: Linux/Unix
...
Finished. Open ports: 2, tested: 1024, timeouts: 0
```

### Output legend

| Output | Meaning |
|--------|---------|
| `[+] N OPEN` | The connection was accepted. If the service sent data, `banner:` and `os guess:` lines follow |
| `[-] N closed/filtered` | Connection refused or immediate failure |
| `[-] N timeout` | No response within 1 s |

Output is **not in ascending port order**: each result is printed as soon as it is ready.

### Why do some open ports show no banner?

The scanner only reads what the service sends on its own. Services such as SSH, FTP,
and SMTP send a banner as soon as you connect. HTTPS (443), SMB (445), RPC (135),
RDP (3389), and many others stay silent until they receive a specific request, so
they appear only as `OPEN`. The `GET /` probe is only sent on ports 80, 8000, 8008,
8080, and 8888.

---

## Building without opening the MSYS2 terminal (optional)

If you prefer PowerShell, call gcc by its full path. Note the **quotes** around the
last argument; PowerShell treats the comma as an operator, so they are required:

```powershell
nasm -f win64 port_scanner.asm -o port_scanner.obj
C:\msys64\mingw64\bin\gcc.exe -nostdlib -o port_scanner.exe port_scanner.obj -lws2_32 -lkernel32 "-Wl,-e,_start"
```

To use `gcc` and `nasm` directly from PowerShell, add `C:\msys64\mingw64\bin` to your
Windows `PATH` (Settings → System → About → Advanced system settings → Environment Variables).

---

## Alternative: Visual Studio (no MSYS2)

In the *x64 Native Tools Command Prompt for VS*:

```
nasm -f win64 port_scanner.asm -o port_scanner.obj
link /subsystem:console /entry:_start /nodefaultlib port_scanner.obj kernel32.lib ws2_32.lib
```

(NASM must be installed: <https://www.nasm.us>.)

---

## Troubleshooting

| Problem | Cause and fix |
|---------|---------------|
| `command not found` with `\302...` before the command | An invisible character was copied along with the text. Type the command by hand, or paste it into a plain text editor first. In MSYS2, paste with **Shift+Insert** |
| PowerShell: `Missing argument in parameter list` | The comma in `-Wl,-e,_start` needs quotes: `"-Wl,-e,_start"` |
| `file not recognized: file format not recognized` | The `.obj` was not generated with `-f win64`, is empty, or `gcc` is the 32-bit one. Delete the `.obj`, re-run `nasm`, and check `gcc -dumpmachine` |
| `nasm: command not found` | The package is not installed or you are in the wrong terminal. Open **MSYS2 MINGW64** and repeat step 2 |
| `undefined reference to WSAPoll` (or another `ws2_32` function) | Order matters: keep `-lws2_32 -lkernel32` **after** the `.obj`, as in the commands above |
| The `.exe` opens and closes immediately | Run it from a terminal (see step 4) |
| Antivirus blocks the `.exe` | Unsigned binaries built with `-nostdlib` sometimes trigger heuristics. If you compiled it yourself, add an exception for the folder |
| Everything shows as `timeout` | A firewall on the target or on your machine may be dropping packets; test against `127.0.0.1` first |

---

## Project layout

```
port_scanner.asm   source code (NASM, Windows x64)
README.md          this file
```

Tunable constants at the top of the `.asm`:

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_INFLIGHT` | 64 | Simultaneous connections |
| `CONNECT_TIMEOUT` | 1000 | ms to wait for `connect` to complete |
| `BANNER_TIMEOUT` | 1000 | ms to wait for a banner after connecting |
| `BANNER_MAX` | 256 | Banner bytes read |
