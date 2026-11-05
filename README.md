# BinInspect

**BinInspect** is a modular static binary analysis tool written in Go. It collects executable metadata, analyzes disassembled instructions, inspects security protections, and produces structured, human-readable terminal reports.

Designed for cybersecurity research, reverse engineering, and binary inspection, BinInspect provides a unified analysis workflow across multiple executable formats without executing the target binary.

## Features

### Multi-Format Support

BinInspect supports four analysis paths:

| Format | Description |
|---|---|
| ELF | Linux and Unix-like executables and shared libraries |
| PE | Windows executables and DLLs |
| Mach-O | macOS executables and libraries |
| Unknown | Unrecognized or raw binary files |

The appropriate collection engine is selected automatically based on the target's format.

### Binary Information Collection

BinInspect collects information such as:

- Executable format, architecture, and entry point
- Program headers, sections, and memory segments
- Symbols and imported functions
- Dynamic libraries and dependencies
- Relocations and debugging information
- Disassembled instructions and raw binary data
- Embedded printable strings
- Available security-related metadata

Collection methods depend on the executable format and the tools available on the host system.

### Assembly Analysis

The assembly analyzer interprets disassembly output to identify:

- Instructions and their addresses
- Function definitions and call sites
- Direct and indirect calls
- Conditional and unconditional branches
- Return instructions
- Common stack allocation patterns
- Caller/callee relationships
- Instruction categories

The analyzer includes initial support for common x86, x86-64, ARM, AArch64, and RISC-V disassembly patterns.

### Security Analysis

BinInspect examines available evidence for security mechanisms, including:

| Protection | Purpose |
|---|---|
| NX | Non-executable memory protections |
| PIE | Position-independent executables |
| RELRO | ELF relocation-related protections |
| Stack Canary | Stack corruption detection |
| ASLR | Address-space randomization compatibility |
| CFG | Control-flow protection indicators |

Protection information is reported according to the evidence available. Missing information does not automatically indicate that a protection is disabled.

### Vulnerability Indicators

BinInspect identifies potentially unsafe functions and security configurations, including:

- Unbounded input functions such as `gets`
- Potentially unsafe string operations
- Unbounded formatted output
- Suspicious imported functions
- Executable stack configurations
- Missing position independence where detectable

Findings include severity, confidence, supporting evidence, and remediation suggestions.

**Important:** A potentially unsafe function or configuration does not automatically establish an exploitable vulnerability. Findings require additional investigation.

### Structured Terminal Reports

Reports use ANSI colors and bordered sections to present:

1. Binary identity
2. Binary structure
3. Assembly analysis
4. Function analysis
5. Collection coverage
6. Security protections
7. Security findings

Security findings are presented in severity order, with concise supporting evidence.

Terminal colors are disabled when output is redirected or the `NO_COLOR` environment variable is set.

---

## Requirements

- Go, using a version compatible with `go.mod`
- Linux environment, recommended for the current collection implementation
- GNU Binutils (`readelf`, `objdump`, `strings`)
- `file` utility
- Optional: LLVM tools for Mach-O disassembly

Some format-specific collection features depend on the host's installed tooling.

## Installation

Clone the repository:

```bash
git clone https://github.com/Des1red/bininspect.git
cd bininspect
```

Install dependencies:

```bash
go mod download
```

Build the executable:

```bash
go build -o bininspect .
```

Alternatively, use the built-in installation command:

```bash
go run . install
```

The installer uses [goinstall](https://github.com/Des1red/goinstall) to build and install BinInspect.

Configured installation locations include:

```text
~/.local/bin/bininspect
/usr/local/bin/bininspect
```

System-wide installation may require elevated privileges.

### Uninstallation

Remove installed binaries:

```bash
bininspect uninstall
```

You can also run the uninstaller from the source directory:

```bash
go run . uninstall
```

---

## Usage

### Inspect a Binary

```bash
bininspect -t /path/to/binary
```

Or:

```bash
bininspect --target /path/to/binary
```

Examples:

Inspect a Linux executable:

```bash
bininspect -t /usr/bin/ls
```

Inspect a challenge binary:

```bash
bininspect -t ./ex00/bin
```

Inspect a Windows executable:

```bash
bininspect -t ./application.exe
```

Inspect a Mach-O binary:

```bash
bininspect -t ./application
```

### Available Commands

| Command | Description |
|---|---|
| `-t, --target` | Select the binary to analyze |
| `-h, --help` | Display help |
| `install` | Build and install BinInspect |
| `uninstall` | Remove installed BinInspect binaries |

---

## Architecture

BinInspect follows a modular architecture that separates collection, analysis, and presentation.

```text
Target Binary
     |
     v
Format Detection
     |
     v
Collection Engine
     |
     +-- ELF Collector
     +-- PE Collector
     +-- Mach-O Collector
     +-- Unknown Collector
     |
     v
models.Knowledge
     |
     v
Analysis Engine
     |
     +-- Identity
     +-- Structure
     +-- Assembly
     +-- Functions
     +-- Security
     +-- Findings
     |
     v
models.Results
     |
     v
Report Engine
     |
     v
Terminal Report
```

### Collection Engine

Located in `internal/collect/`.

The collection engine executes the appropriate format-specific collectors and stores their returned information in `models.Knowledge`.

Individual collectors do not directly populate the knowledge model.

### Analysis Engine

Located in `internal/analyzer/`.

The analyzer reads collected information and generates structured results covering executable identity, binary structure, instructions, functions, security properties, and potential risks.

The analysis engine coordinates specialized modules and populates `models.Results`.

### Reporting Engine

Located in `internal/report/`.

The reporting engine reads `models.Results` and presents relevant information in a consistent terminal layout.

Raw collection output is summarized rather than printed in full.

### Bootstrap

Located in `internal/bootstrap/`.

The bootstrap module manages installation and uninstallation through the external `goinstall` library.

---

## Project Structure

```text
bininspect/
├── cmd/
│   ├── flags.go
│   └── root.go
├── internal/
│   ├── activate.go
│   ├── engine.go
│   ├── analyzer/
│   │   ├── assembly.go
│   │   ├── engine.go
│   │   ├── findings.go
│   │   ├── functions.go
│   │   ├── helpers.go
│   │   ├── identity.go
│   │   ├── security.go
│   │   └── structure.go
│   ├── bootstrap/
│   │   ├── install.go
│   │   └── uninstall.go
│   ├── collect/
│   │   ├── common.go
│   │   ├── elf.go
│   │   ├── engine.go
│   │   ├── macho.go
│   │   ├── pe.go
│   │   ├── runner.go
│   │   └── unkown.go
│   ├── models/
│   │   ├── knowledge.go
│   │   ├── results.go
│   │   └── scope.go
│   └── report/
│       ├── engine.go
│       ├── findings.go
│       ├── overview.go
│       ├── security.go
│       └── style.go
├── go.mod
├── go.sum
└── main.go
```

## Limitations

BinInspect is an evolving static analysis project.

Current limitations include:

- Assembly interpretation is based on recognizable disassembly patterns rather than a complete instruction decoder.
- Indirect function calls may not be resolvable statically.
- Some information may be unavailable in stripped binaries.
- Security protection detection is based on available metadata and heuristics.
- Format-specific analysis capabilities differ.
- Complete control-flow graph reconstruction is not yet implemented.
- Register-level data-flow, memory tracking, and taint analysis remain future development areas.
- Findings do not prove vulnerability exploitability.
- Malformed or adversarial binary files may require additional isolation and resource controls.

BinInspect does not execute the inspected binary or automatically exploit identified vulnerabilities.

---

## Development

Format the project:

```bash
gofmt -w ./cmd ./internal
```

Run tests:

```bash
go test ./...
```

Build:

```bash
go build -o bininspect .
```

### Future Development

Potential improvements include:

- Register and memory-state tracking
- Control-flow graph reconstruction
- Cross-instruction data-flow analysis
- Stack-variable and buffer-boundary identification
- Improved PE and Mach-O metadata extraction
- Expanded architecture support
- Enhanced vulnerability evidence correlation
- JSON and Markdown report export
- Automated regression tests using representative binaries

---

## Ethical Use

BinInspect is intended for educational purposes, authorized security research, reverse engineering, and defensive software analysis.

Only analyze software or systems for which you have appropriate authorization.

The tool's findings should be independently verified before making security claims or applying remediation.

## Dependencies

- [Go](https://go.dev/)
- [pflag](https://github.com/spf13/pflag)
- [clihelp](https://github.com/Des1red/clihelp)
- [goinstall](https://github.com/Des1red/goinstall)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
---

**BinInspect — Collect. Analyze. Understand.**

Copyright (c) 2026 Des1red