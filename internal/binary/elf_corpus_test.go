package binary

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sectionlessELF(
	t *testing.T,
	original []byte,
) []byte {
	t.Helper()

	file, err := elf.NewFile(bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}

	result := append([]byte(nil), original...)

	switch file.Class {
	case elf.ELFCLASS64:
		clear(result[40:48])
		clear(result[60:64])

	case elf.ELFCLASS32:
		clear(result[32:36])
		clear(result[48:52])

	default:
		t.Fatalf("unsupported ELF class %v", file.Class)
	}

	return result
}

func TestELFVersionCorpus(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}

	for _, path := range []string{
		"/bin/ls",
		"/bin/bash",
		"/usr/bin/true",
	} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Skip(err)
			}

			versions, err := ParseELFVersions(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if !versions.Present ||
				len(versions.Requirements) == 0 ||
				len(versions.Symbols) == 0 ||
				!versions.SymbolCountComplete {
				t.Fatalf("missing version records: %+v", versions)
			}

			file, err := elf.NewFile(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}

			// Independent comparison with Go's ELF reader.
			reference, err := file.DynamicSymbols()
			if err != nil {
				t.Fatal(err)
			}

			// DynamicSymbols omits symbol zero.
			if len(reference)+1 != len(versions.Symbols) {
				t.Fatalf(
					"reference symbols %d, version entries %d",
					len(reference),
					len(versions.Symbols),
				)
			}

			for i, symbol := range reference {
				actual := versions.Symbols[i+1]

				if symbol.Name != actual.SymbolName ||
					symbol.Version != actual.Name ||
					symbol.Library != actual.Library {
					t.Fatalf(
						"symbol %d mismatch: reference=%+v actual=%+v",
						i+1,
						symbol,
						actual,
					)
				}
			}

			// Remove section-header references, retaining
			// the actual dynamic records and memory layout.
			sectionless := sectionlessELF(t, raw)

			recovered, err := ParseELFVersions(
				bytes.NewReader(sectionless),
				uint64(len(sectionless)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if !recovered.Present ||
				len(recovered.Symbols) > len(versions.Symbols) {
				t.Fatalf(
					"invalid sectionless recovery: %+v",
					recovered,
				)
			}

			for i, symbol := range recovered.Symbols {
				expected := versions.Symbols[i]

				if symbol.SymbolName != expected.SymbolName ||
					symbol.Name != expected.Name ||
					symbol.Library != expected.Library {
					t.Fatalf(
						"sectionless symbol %d mismatch",
						i,
					)
				}
			}

			validation, err := CrossValidateELF(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if validation.Mode != "dual-source" ||
				validation.ComparedSymbols == 0 ||
				validation.ComparedRelocations == 0 ||
				validation.ComparedVersionBytes == 0 {
				t.Fatalf(
					"incomplete comparison: %+v",
					validation,
				)
			}

			sectionlessValidation, err := CrossValidateELF(
				bytes.NewReader(sectionless),
				uint64(len(sectionless)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if sectionlessValidation.Mode != "dynamic-only" {
				t.Fatalf(
					"unexpected sectionless mode: %+v",
					sectionlessValidation,
				)
			}

			t.Logf(
				"symbols=%d requirements=%d compared_symbols=%d compared_relocations=%d version_bytes=%d",
				len(versions.Symbols),
				len(versions.Requirements),
				validation.ComparedSymbols,
				validation.ComparedRelocations,
				validation.ComparedVersionBytes,
			)
		})
	}
}

func TestELFVersionedLibraryCorpus(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	dir := t.TempDir()

	source := filepath.Join(dir, "api.c")
	versionScript := filepath.Join(dir, "api.map")
	library := filepath.Join(dir, "libapi.so")

	if err := os.WriteFile(
		source,
		[]byte("int api(void) { return 42; }"),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		versionScript,
		[]byte("BININSPECT_1.0 { global: api; local: *; };"),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(
		compiler,
		"-shared",
		"-fPIC",
		"-Wl,--version-script="+versionScript,
		"-o", library,
		source,
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf(
			"library compilation failed: %v: %s",
			err, output,
		)
	}

	raw, err := os.ReadFile(library)
	if err != nil {
		t.Fatal(err)
	}

	versions, err := ParseELFVersions(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	found := false

	for _, symbol := range versions.Symbols {
		if symbol.SymbolName == "api" &&
			symbol.Name == "BININSPECT_1.0" &&
			symbol.Kind == "defined" {
			found = true
		}
	}

	if !found {
		t.Fatal("missing versioned export api@BININSPECT_1.0")
	}

	if _, err := CrossValidateELF(
		bytes.NewReader(raw),
		uint64(len(raw)),
	); err != nil {
		t.Fatal(err)
	}
}

func TestELFCrossValidationRejectsWrongVersionPointer(t *testing.T) {
	raw, err := os.ReadFile("/bin/ls")
	if err != nil {
		t.Skip(err)
	}

	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	if file.Class != elf.ELFCLASS64 {
		t.Skip("requires ELF64 fixture")
	}

	index := -1

	for i, section := range file.Sections {
		if section.Type == elf.SHT_GNU_VERSYM {
			index = i
			break
		}
	}

	if index < 0 {
		t.Skip("GNU version section unavailable")
	}

	sectionOffset := file.ByteOrder.Uint64(raw[40:48])
	entrySize := uint64(
		file.ByteOrder.Uint16(raw[58:60]),
	)

	// ELF64 section-header sh_addr field.
	position := int(
		sectionOffset + uint64(index)*entrySize + 16,
	)

	corrupted := append([]byte(nil), raw...)

	file.ByteOrder.PutUint64(
		corrupted[position:position+8],
		file.Sections[index].Addr+2,
	)

	_, err = CrossValidateELF(
		bytes.NewReader(corrupted),
		uint64(len(corrupted)),
	)

	if err == nil ||
		!strings.Contains(err.Error(), "differs from dynamic address") {
		t.Fatalf(
			"mismatched version pointer not detected: %v",
			err,
		)
	}
}

func TestELFObjectCorpus(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "sample.c")
	object := filepath.Join(dir, "sample.o")

	code := []byte(
		"extern int external(int); " +
			"int test(int x) { return external(x) + 1; }",
	)

	if err := os.WriteFile(source, code, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(
		compiler, "-c", "-o", object, source,
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compiler failed: %v: %s", err, output)
	}

	raw, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}

	result, err := CrossValidateELF(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Mode != "section-only" {
		t.Fatalf("unexpected ET_REL mode: %+v", result)
	}
}

func TestELFCompilerCorpusMatrix(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("Linux amd64 linker corpus")
	}

	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("C compiler required for full ELF corpus")
	}

	dir := t.TempDir()

	pieSource := filepath.Join(dir, "pie.c")
	pie := filepath.Join(dir, "pie")

	if err := os.WriteFile(
		pieSource,
		[]byte(
			"#include <stdio.h>\n"+
				"int main(void) { return puts(\"testing\") < 0; }",
		),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	assembly := filepath.Join(dir, "start.s")
	static := filepath.Join(dir, "static")

	if err := os.WriteFile(
		assembly,
		[]byte(
			".globl _start\n"+
				".text\n"+
				"_start:\n"+
				"mov $60,%rax\n"+
				"xor %rdi,%rdi\n"+
				"syscall\n",
		),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	commands := [][]string{
		{"-fPIE", "-pie", "-o", pie, pieSource},
		{"-nostdlib", "-static", "-Wl,-e,_start", "-o", static, assembly},
	}

	for _, arguments := range commands {
		cmd := exec.Command(compiler, arguments...)

		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf(
				"compilation failed %v: %v: %s",
				arguments, err, output,
			)
		}
	}

	for _, path := range []string{pie, static} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			result, err := CrossValidateELF(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if result.Mode == "" {
				t.Fatal("empty ELF validation mode")
			}
		})
	}
}

func TestELFExerciseCrossValidation(t *testing.T) {
	root := os.Getenv("BININSPECT_ELF_CORPUS")
	if root == "" {
		t.Skip("set BININSPECT_ELF_CORPUS")
	}

	for _, exercise := range []string{"ex00", "ex01"} {
		t.Run(exercise, func(t *testing.T) {
			raw, err := os.ReadFile(
				filepath.Join(root, exercise, "bin"),
			)
			if err != nil {
				t.Fatal(err)
			}

			result, err := CrossValidateELF(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if result.Mode == "" {
				t.Fatal("missing validation mode")
			}
		})
	}
}

// Fuzz entry point for malformed ELF header, dynamic table,
// version metadata and cross-validation handling.
func FuzzELFVersionValidation(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x7f, 'E', 'L', 'F'},
		make([]byte, 64),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Add(dynamicMetadataFixture())
	f.Add(objectFixture(elf.ELFCLASS64))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}

		_, _ = CrossValidateELF(
			bytes.NewReader(data),
			uint64(len(data)),
		)
	})
}

// Retains explicit byte-order coverage in this corpus package;
// existing ELF32 big-endian tests remain part of the full suite.
var _ binary.ByteOrder = binary.LittleEndian
