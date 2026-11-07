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

func TestExtendedProgramHeadersActual(t *testing.T) {
	const count = 65536
	const phOff = 64
	const shOff = 0x3c0000
	const codeOff = 0x400000

	raw := make([]byte, codeOff+4)

	copy(raw[:4], "\x7fELF")
	raw[4] = 2
	raw[5] = 1
	raw[6] = 1

	bo := binary.LittleEndian

	bo.PutUint16(raw[16:], uint16(elf.ET_EXEC))
	bo.PutUint16(raw[18:], uint16(elf.EM_X86_64))
	bo.PutUint32(raw[20:], 1)
	bo.PutUint64(raw[24:], 0x400000)
	bo.PutUint64(raw[32:], phOff)
	bo.PutUint64(raw[40:], shOff)

	bo.PutUint16(raw[52:], 64)
	bo.PutUint16(raw[54:], 56)
	bo.PutUint16(raw[56:], 0xffff)
	bo.PutUint16(raw[58:], 64)
	bo.PutUint16(raw[60:], 1)

	// The actual program count lives in section zero.
	bo.PutUint32(raw[shOff+44:], count)

	p := raw[phOff:]

	bo.PutUint32(p[0:], uint32(elf.PT_LOAD))
	bo.PutUint32(p[4:], uint32(elf.PF_R|elf.PF_X))
	bo.PutUint64(p[8:], codeOff)
	bo.PutUint64(p[16:], 0x400000)
	bo.PutUint64(p[32:], 4)
	bo.PutUint64(p[40:], 4)
	bo.PutUint64(p[48:], 1)

	copy(raw[codeOff:], []byte{0x90, 0x90, 0x90, 0xc3})

	reader := bytes.NewReader(raw)

	tables, err := inspectELFTables(
		reader, uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if tables.programCount != count {
		t.Fatalf(
			"program count=%d, expected %d",
			tables.programCount, count,
		)
	}

	file, err := elf.NewFile(reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := appendExtendedELFPrograms(
		file, reader, uint64(len(raw)), tables,
	); err != nil {
		t.Fatal(err)
	}

	if len(file.Progs) != count {
		t.Fatalf(
			"decoded %d program headers, expected %d",
			len(file.Progs), count,
		)
	}

	// Also verify the public loader.
	image, err := ParseELF(
		bytes.NewReader(raw), uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if image.Info.Entry != 0x400000 {
		t.Fatalf("wrong entry: %#x", image.Info.Entry)
	}
}

func TestExtendedSectionHeaderCount(t *testing.T) {
	const count = 0xff00
	const offset = 64

	raw := make([]byte, offset+count*64)

	copy(raw[:4], "\x7fELF")
	raw[4] = 2
	raw[5] = 1
	raw[6] = 1

	bo := binary.LittleEndian

	bo.PutUint16(raw[16:], uint16(elf.ET_REL))
	bo.PutUint16(raw[18:], uint16(elf.EM_X86_64))
	bo.PutUint32(raw[20:], 1)

	bo.PutUint64(raw[40:], offset)
	bo.PutUint16(raw[52:], 64)
	bo.PutUint16(raw[58:], 64)
	bo.PutUint16(raw[60:], 0)

	bo.PutUint64(raw[offset+32:], count)

	tables, err := inspectELFTables(
		bytes.NewReader(raw), uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if tables.sectionCount != count {
		t.Fatalf(
			"wrong section count: %d",
			tables.sectionCount,
		)
	}

	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	if len(file.Sections) != count {
		t.Fatalf(
			"parsed %d sections, expected %d",
			len(file.Sections), count,
		)
	}
}

func TestOverlappingLoadRegions(t *testing.T) {
	a := Region{
		Name:        "a",
		Address:     0x1000,
		MemorySize:  16,
		FileOffset:  0x100,
		FileSize:    16,
		Permissions: PermRead | PermExecute,
	}

	b := Region{
		Name:        "b",
		Address:     0x1008,
		MemorySize:  16,
		FileOffset:  0x108,
		FileSize:    16,
		Permissions: PermRead | PermExecute,
	}

	got, err := normalizeELFLoadRegions(
		[]Region{a, b},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 ||
		got[0].MemorySize != 24 ||
		got[0].FileSize != 24 {
		t.Fatalf("unexpected normalized mappings: %+v", got)
	}

	b.Permissions = PermRead

	if _, err := normalizeELFLoadRegions(
		[]Region{a, b},
	); err == nil {
		t.Fatal("accepted conflicting permissions")
	}

	b.Permissions = a.Permissions
	b.FileOffset = 0x200

	if _, err := normalizeELFLoadRegions(
		[]Region{a, b},
	); err == nil {
		t.Fatal("accepted conflicting file mappings")
	}
}

func TestOverlappingZeroFill(t *testing.T) {
	a := Region{
		Name:        "a",
		Address:     0x1000,
		MemorySize:  16,
		FileOffset:  0x100,
		FileSize:    8,
		Permissions: PermRead,
	}

	b := Region{
		Name:        "b",
		Address:     0x1008,
		MemorySize:  16,
		FileOffset:  0x108,
		FileSize:    0,
		Permissions: PermRead,
	}

	got, err := normalizeELFLoadRegions(
		[]Region{a, b},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 ||
		got[0].MemorySize != 24 ||
		got[0].FileSize != 8 {
		t.Fatalf("incorrect zero-fill mapping: %+v", got)
	}

	b.FileSize = 8

	if _, err := normalizeELFLoadRegions(
		[]Region{a, b},
	); err == nil {
		t.Fatal("accepted file-backed/zero-fill conflict")
	}
}

func TestELFMetadataCompiler(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "test.c")
	output := filepath.Join(dir, "test.o")

	code := []byte(
		"extern int target(int); " +
			"int foo(int x) { return target(x) + 1; }",
	)

	if err := os.WriteFile(source, code, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(
		cc, "-c", "-fno-pic", "-o", output, source,
	)

	if result, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compiler failed: %s: %v", result, err)
	}

	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}

	metadata, err := ParseELFMetadata(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	foundSymbol := false
	foundRelocation := false

	for _, symbol := range metadata.Symbols {
		if symbol.Name == "target" {
			foundSymbol = true
		}
	}

	for _, relocation := range metadata.Relocations {
		if relocation.SymbolName == "target" {
			foundRelocation = true
		}
	}

	if !foundSymbol || !foundRelocation {
		t.Fatalf(
			"symbol found=%v relocation found=%v",
			foundSymbol, foundRelocation,
		)
	}

	// Corrupt the symbol index in a 64-bit RELA entry.
	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	if file.Class != elf.ELFCLASS64 {
		return
	}

	for _, section := range file.Sections {
		if section.Type != elf.SHT_RELA ||
			section.Size < 24 {
			continue
		}

		corrupt := append([]byte(nil), raw...)
		position := int(section.Offset) + 8

		info := file.ByteOrder.Uint64(
			corrupt[position : position+8],
		)

		info = (uint64(0xffffffff) << 32) |
			uint64(uint32(info))

		file.ByteOrder.PutUint64(
			corrupt[position:position+8], info,
		)

		_, err := ParseELFMetadata(
			bytes.NewReader(corrupt),
			uint64(len(corrupt)),
		)

		if err == nil ||
			!strings.Contains(err.Error(), "invalid symbol index") {
			t.Fatalf(
				"invalid symbol index was not rejected: %v",
				err,
			)
		}

		break
	}
}

func TestRELRExpansion(t *testing.T) {
	file := &elf.File{
		FileHeader: elf.FileHeader{
			Class:     elf.ELFCLASS64,
			Type:      elf.ET_DYN,
			ByteOrder: binary.LittleEndian,
		},
	}

	var data [16]byte

	binary.LittleEndian.PutUint64(data[0:], 0x2000)
	binary.LittleEndian.PutUint64(data[8:], 0b1011)

	metadata := ELFMetadata{}

	section := &elf.Section{
		SectionHeader: elf.SectionHeader{
			Type:    elfSHTRELR,
			Entsize: 8,
		},
	}

	if err := parseELFRELR(
		&metadata, 3, section, data[:], file,
	); err != nil {
		t.Fatal(err)
	}

	expected := []uint64{0x2000, 0x2008, 0x2018}

	if len(metadata.Relocations) != len(expected) {
		t.Fatalf(
			"expected %d relocations, got %d",
			len(expected), len(metadata.Relocations),
		)
	}

	for i, address := range expected {
		if metadata.Relocations[i].Offset != address {
			t.Fatalf(
				"relocation %d: got %#x, expected %#x",
				i,
				metadata.Relocations[i].Offset,
				address,
			)
		}
	}

	if err := parseELFRELR(
		&ELFMetadata{},
		3,
		section,
		[]byte{1, 0, 0, 0, 0, 0, 0, 0},
		file,
	); err == nil {
		t.Fatal("accepted RELR bitmap without a base")
	}
}

func TestELFMetadataRealExecutables(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}

	for _, path := range []string{
		"/bin/ls",
		"/bin/bash",
		"/usr/bin/true",
	} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			file, err := os.Open(path)
			if err != nil {
				t.Skip(err)
			}
			defer file.Close()

			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}

			metadata, err := ParseELFMetadata(
				file, uint64(info.Size()),
			)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf(
				"symbols=%d relocations=%d",
				len(metadata.Symbols),
				len(metadata.Relocations),
			)
		})
	}
}
