# BinInspect

**BinInspect** is a portable command-line static analyzer for ELF binaries, written in Go. It decodes executable code, reconstructs control flow and function boundaries, performs selected data-flow and security checks, and produces a readable report **without running the target binary**.

> **Current scope:** ELF is the implemented analysis pipeline. PE, Mach-O, and arbitrary raw binaries are **not** supported by the current analyzer. Architecture coverage and analysis depth vary; see [Limitations](#limitations).

## Features

### Structured ELF inspection

- Parses ELF32 and ELF64 metadata, including file identity, architecture, endianness, entry point, program headers, and section headers.
- Collects available symbols, dynamic dependencies, relocations, notes, and relevant dynamic metadata.
- Handles executable, shared-object/PIE, and relocatable ELF inputs where supported by the corresponding decoding path.
- Uses an in-process virtual-address image reader to access file-backed code and data.

### Instruction decoding and control flow

- Decodes instructions with architecture-specific Go decoders. The codebase includes x86/x86-64, ARM/Thumb, AArch64, and RISC-V 64-bit decoding paths; coverage is not identical across architectures.
- Identifies calls, jumps, conditional branches, returns, and instruction-level targets when statically available.
- Constructs basic blocks and control-flow graphs (CFGs) for decoded executable regions.
- Recovers function entries from ELF symbols, the entry point, direct-call evidence, `.eh_frame` unwind ranges, and `.preinit_array` / `.init_array` / `.fini_array` pointers.
- Resolves supported, bounded x86-64 relative-offset jump tables and uses validated targets to extend the CFG.
- Resolves supported PLT call targets using ELF relocation and symbol evidence.

### Data-flow analysis

- Tracks selected register values and stack-pointer relationships, primarily for x86/x86-64.
- Associates decoded call sites with recovered functions and attempts to infer argument facts where supported.
- Distinguishes known abstract values from unknown or partially modeled results.
- Reports decoded calls that cannot be attributed to recovered-function analysis rather than inventing argument values.

**Call-site attribution is not proof of argument correctness or complete runtime path coverage.**

### Security analysis

Reports evidence for ELF security properties including:

| Property | What BinInspect examines |
| --- | --- |
| NX / executable stack | `PT_GNU_STACK` permissions |
| PIE | ELF type and applicable dynamic flags |
| RELRO | `PT_GNU_RELRO` and immediate-binding flags |
| Stack canaries | Available stack-protector symbol evidence |
| FORTIFY | Fortified function-wrapper evidence |
| ASLR compatibility | Relocatable executable properties |
| RWX segments | Executable and writable `PT_LOAD` segments |

Rule-based findings identify conditions worth reviewing. A finding does not establish exploitability, and **zero findings does not prove that a binary is secure**.

### Reports

BinInspect prints a structured terminal report covering:

1. Binary identity
2. Binary structure
3. Decoded instruction candidates
4. Control flow
5. Function recovery
6. Data-flow analysis
7. Security protections
8. Security findings
9. Analysis summary

A Markdown analysis report is also saved; for example, inspecting `/bin/ls` produces `ls_bininspect.md`.

## Requirements

- Go version compatible with [`go.mod`](go.mod).
- Go module dependencies fetched during the build.

**No external disassembly or ELF command-line utilities are required at runtime.** In particular, BinInspect does not depend on `readelf`, `objdump`, `strings`, or `file` to perform its analysis. The analyzer uses Go code and does not require CGo.

## Build and installation

```bash
git clone https://github.com/Des1red/bininspect.git
cd bininspect
go mod download
CGO_ENABLED=0 go build -o bininspect .
```

Run the locally built executable:

```bash
./bininspect -t /bin/ls
```

BinInspect also includes installation and uninstallation commands:

```bash
go run . install
bininspect uninstall
```

The bootstrap implementation uses the [`goinstall`](https://github.com/Des1red/goinstall) Go library. Installation location and permissions depend on the selected installation mode.

## Usage

```bash
bininspect -t /path/to/binary
bininspect --target /path/to/binary
bininspect -h
```

Examples:

```bash
# Inspect a system ELF executable
./bininspect -t /bin/ls

# Inspect a local challenge ELF binary
./bininspect -t ./ex00/bin

# Run directly from the source tree
go run . -t /bin/ls
```

| Option / command | Purpose |
| --- | --- |
| `-t`, `--target` | Path to the ELF binary to inspect |
| `-h`, `--help` | Show command help |
| `install` | Install the BinInspect executable |
| `uninstall` | Remove an installed BinInspect executable |

## How it works

```text
Target ELF binary
       |
       v
Structured ELF parsing + mapped image
       |
       v
Architecture-specific instruction decoding
       |
       v
Initial CFG + function-entry leaders
       |
       v
Validated jump-table target resolution
       |
       v
Final CFG + function recovery
       |   (symbols, calls, .eh_frame, runtime arrays)
       v
Data-flow and call-site analysis
       |
       +--> Security protections and rule-based findings
       |
       v
Terminal report + Markdown report
```

The main implementation is organized as follows:

```text
cmd/                         CLI flags and commands
internal/
  binary/                    ELF parsing, metadata, virtual image
  collect/                   Binary collection pipeline
  decoder/                   Architecture-specific instruction decoders
  analyzer/
    cfg/                     Basic blocks and CFG construction
    functions/               Unwind-guided and runtime-array recovery
    resolve/                 PLT and bounded jump-table resolution
    dataflow/                Abstract values, stack and call-site analysis
    security/                ELF security-property detection
    findings/                Rule-based findings
  report/                    Terminal and Markdown reporting
  bootstrap/                 Install and uninstall commands
  runner.go                  Application orchestration
main.go                       CLI entry point
```

## Verified milestone: ELF function recovery

**16 November 2026 — Function recovery and call-site attribution milestone.** The Fedora `/bin/ls` sample used during development produced:

| Metric | Observed result |
| --- | ---: |
| Decoded instruction candidates | 22,705 |
| CFG basic blocks | 6,543 |
| CFG edges | 9,005 |
| Recovered function candidates | 198 |
| Decoded call sites | 1,164 |
| Calls attributed to recovered-function data flow | 1,164 |
| Unattributed calls | 0 |
| Multiply owned call sites | 0 |
| Decoder diagnostics | 0 |

This is **100% call-site attribution for that specific binary**, not a general guarantee for all ELF files, nor a claim that every argument or branch target is known.

## Development and tests

Format Go sources:

```bash
gofmt -w cmd internal main.go
```

Run the full test suite, race checks, static checks, and build:

```bash
CGO_ENABLED=0 go test -count=1 ./...
CGO_ENABLED=1 go test -race -count=1 ./internal/analyzer/...
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go build -o bininspect .
```

The project has focused tests for ELF parsing, decoding, CFG construction, `.eh_frame` recovery, runtime-array recovery, PLT resolution, jump tables, data flow, security analysis, and report generation. Some local `*_probe_test.go` files are diagnostic experiments tied to the host's `/bin/ls`; their numerical results are not portable regression expectations.

## Limitations

- The current end-to-end analyzer targets **ELF**; PE, Mach-O, and unknown/raw-format analysis are not implemented.
- Static decoding and CFG reconstruction are conservative. Computed branches, dynamically resolved targets, and some hand-written or obfuscated code may remain unresolved.
- `.eh_frame` and runtime-array metadata may be incomplete or absent. Runtime-array pointer handling currently relies on stored addresses and does not fully account for every ELF relocation scheme.
- The supported jump-table patterns are bounded and validated; not every indirect branch is resolved.
- Data-flow inference models a subset of instructions and states; abstract values are not proven runtime values or buffer bounds. Non-x86 architectures have different analysis coverage.
- Security-property results describe file metadata and static evidence, not necessarily active runtime enforcement.
- A clean report cannot establish that a binary is safe or free of vulnerabilities.

BinInspect **does not execute the inspected program** or attempt exploitation.

## Ethical use

Use BinInspect for education, reverse engineering, defensive security analysis, and research on software you are authorized to inspect. Independently verify any findings before making security claims.

## License

Distributed under the [MIT License](LICENSE).

**BinInspect — Collect. Analyze. Understand.**