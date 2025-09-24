# RBear

RBear is a cross-platform cli tool for parsing and inspecting **PE**, **ELF**, and **Mach-O** binaries.

## Features

### PE (Portable Executable)

* DOS and NT headers parsing
* Section table listing
* Timestamp, machine type, entry point
* Import table parsing (DLLs and functions)
* Export table parsing (functions and ordinals)

### ELF (Executable and Linkable Format)

* Class (32-bit / 64-bit) and endianness detection
* Entry point address
* Section header parsing
* Imported symbol detection from `.dynamic`
* Exported symbol listing from `.symtab`

### Mach-O

* Format detection
* Header information
* (Planned) Section and symbol parsing

## Requirements

* Rust (latest stable recommended)
* Cargo

## Installation

```bash
git clone https://github.com/Nexriel/RBear.git
cd RBear
cargo build --release
```

The compiled binary will be located in `target/release`.

## Usage

```bash
./RBear path/to/binary
```

Example:

```bash
./RBear /bin/ls
```

## Dependencies

* [anyhow](https://docs.rs/anyhow) – error handling
* [scroll](https://docs.rs/scroll) – binary parsing
* [chrono](https://docs.rs/chrono) – timestamp handling

## Sample Output

### PE Example (`kernel32.dll`)

```
File: kernel32.dll
Format: PE (Portable Executable)
Machine: 0x8664
Sections: 6
Timestamp: 2024-02-15 11:42:33 UTC
Entry Point RVA: 0x180010000

Sections:
  .text    | VA: 0x1000 | VS: 987456 | RS: 985600
  .rdata   | VA: 0xF2000 | VS: 245760 | RS: 243200
  .data    | VA: 0x130000 | VS: 32768 | RS: 1024

Imports:
  KERNELBASE.dll
    GetProcAddress
    LoadLibraryA
    VirtualAlloc

Exports:
  0x180020100  AddAtomA (Ordinal 10)
  0x180020140  CloseHandle (Ordinal 25)
```

### ELF Example (`/bin/ls`)

```
File: /bin/ls
Format: ELF
Class: 64-bit
Endian: Little
Entry point: 0x4010B0

Sections:
  .interp     | Offset: 0x238 | Size: 28
  .dynsym     | Offset: 0x400 | Size: 576
  .dynstr     | Offset: 0x700 | Size: 832
  .text       | Offset: 0x1000 | Size: 16400

Imports:
  libc.so.6
    printf
    opendir
    readdir

Exports:
  main
  _start
```