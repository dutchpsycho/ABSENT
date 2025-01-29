# ABSENT

![ABSENT](.idea/EXAMPLE.gif)

## Table of Contents

- [ABSENT](#absent)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Features](#features)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Clone the Repo](#clone-the-repo)
    - [Build the Project](#build-the-project)
    - [Running ABSENT](#running-absent)
    - [Example](#example)
    - [Output](#output)
  - [Contributing](#contributing)

## Overview

**ABSENT** is a sophisticated hook detection tool designed for Windows x64 systems (Windows 10 & 11). Written in Rust with future plans to incorporate C, ABSENT leverages low-level system interactions to identify and analyze various forms of hooks and tampering within running processes. Primarily targeted towards red-team operations and offensive security assessments, ABSENT provides a robust framework for detecting inline hooks, IAT/EAT modifications, syscall redirections, and more.

## Features

- **Import Address Table (IAT) Hook Detection**
  - Enumerates loaded modules and verifies the integrity of imported function addresses.
  
- **Export Address Table (EAT) Verification**
  - Ensures exported functions in critical DLLs like `ntdll.dll` and `kernel32.dll` are unaltered.
  
- **Function scanning**
  - Detects common trampoline instructs (`jmp`, `call`, `mov rax, addr`).
  
- **Syscall Redirection Detection**
  - Compares syscall stubs against kernel expectations to spot redirections or modifications (Hooks on ``syscall``).

## Installation

### Prerequisites

This is a x64 project. I do not know if this supports x86. I do not attempt to support x86. I develop on x64.

- **Rust**: Ensure you have Rust installed. If not, download it from [rust-lang.org](https://www.rust-lang.org/tools/install).
- **LLVM Nightly**: ABSENT requires the LLVM nightly compiler. Install it using Rustup:

  ```sh
  rustup install nightly
  rustup default nightly
  ```

### Clone the Repo

```sh
git clone https://github.com/dutchpsycho/ABSENT.git
cd ABSENT
```

### Build the Project

```sh
cargo build --release
```

The executable will be located in the `target/release` directory.

### Running ABSENT

```sh
./ABSENT <ProcName/WndwTitle>
```

### Example

```sh
./ABSENT notepad.exe
```

or

```sh
./ABSENT "Untitled - Notepad"
```

Or, you can run ``ABSENT.exe`` and use the cl directly

### Output

ABSENT will display the process and thread handles along with the PID. It will then perform the hook detection analysis and inform you if any hooks are detected.

```sh
Process handle: Some()
Thread handle: Some()
PID: 1234
No hooks detected. Analysis complete.
```

## Contributing

Contributions are welcome. Your involvement helps me improve.

---

*Disclaimer: ABSENT is intended for educational and authorized security testing purposes only. Unauthorized use of this tool may be illegal and unethical.*
