package decoder

import (
	"bytes"
	"debug/elf"
	stdbinary "encoding/binary"
	"testing"

	"bininspect/internal/binary"
)

func testELFImage(
	t *testing.T,
	arch binary.Architecture,
	code []byte,
) *binary.ELFResult {
	t.Helper()

	bits := uint8(32)

	switch arch {
	case binary.ArchX8664,
		binary.ArchARM64,
		binary.ArchRISCV64:
		bits = 64
	}

	info := binary.Info{
		Format:       binary.FormatELF,
		Architecture: arch,
		Bits:         bits,
		Endianness:   binary.LittleEndian,
		Entry:        0x401000,
	}

	image, err := binary.NewImage(
		bytes.NewReader(code),
		uint64(len(code)),
		info,
		[]binary.Region{{
			Name:       "PT_LOAD[0]",
			Address:    0x401000,
			MemorySize: uint64(len(code)),
			FileSize:   uint64(len(code)),
			Permissions: binary.PermRead |
				binary.PermExecute,
		}},
	)

	if err != nil {
		t.Fatal(err)
	}

	return &binary.ELFResult{
		Info:  info,
		Image: image,
	}
}

func TestEngineExecutableAndRelocations(t *testing.T) {
	// nop; call +0; ret
	parsed := testELFImage(
		t,
		binary.ArchX8664,
		[]byte{0x90, 0xe8, 0, 0, 0, 0, 0xc3},
	)

	parsed.Metadata.Relocations = []binary.ELFRelocation{{
		Section:     2,
		Offset:      0x401002,
		Type:        4,
		SymbolIndex: 1,
		SymbolName:  "external",
		Encoding:    "RELA",
	}}

	got, err := Engine(parsed)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Sections) != 1 ||
		len(got.Sections[0].Instructions) != 3 ||
		got.Sections[0].Instructions[1].Flow != FlowCall ||
		got.Sections[0].Instructions[2].Flow != FlowReturn {
		t.Fatalf("bad code result: %+v", got)
	}

	refs := got.Sections[0].Instructions[1].Relocations

	if len(refs) != 1 ||
		refs[0].WithinInsn != 1 ||
		refs[0].SymbolName != "external" {
		t.Fatalf("relocation not attached: %+v", refs)
	}
}

func TestEngineThumbMappingSymbol(t *testing.T) {
	parsed := testELFImage(
		t,
		binary.ArchARM,
		[]byte{0x00, 0xbf, 0x70, 0x47},
	)

	parsed.Metadata.Symbols = []binary.ELFSymbol{{
		Name:  "$t",
		Value: 0x401000,
	}}

	got, err := Engine(parsed)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Sections) != 1 ||
		len(got.Sections[0].Instructions) != 2 ||
		got.Sections[0].Instructions[0].Mode != ModeThumb ||
		got.Sections[0].Instructions[1].Flow != FlowReturn {
		t.Fatalf("Thumb mode not selected: %+v", got)
	}
}

func TestEngineUndecodableTail(t *testing.T) {
	parsed := testELFImage(
		t,
		binary.ArchX8664,
		[]byte{0x90, 0x0f},
	)

	got, err := Engine(parsed)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Sections) != 1 ||
		len(got.Sections[0].Instructions) != 1 ||
		got.SkippedBytes != 1 ||
		len(got.Diagnostics) != 1 {
		t.Fatalf(
			"invalid instruction not reported: %+v",
			got,
		)
	}
}

func TestEngineRelocatableObject(t *testing.T) {
	// Minimal ELF64 ET_REL with .text and .shstrtab.
	raw := make([]byte, 0x200)

	copy(raw[:4], "\x7fELF")
	raw[4], raw[5], raw[6] = 2, 1, 1

	bo := stdbinary.LittleEndian

	bo.PutUint16(raw[16:], uint16(elf.ET_REL))
	bo.PutUint16(raw[18:], uint16(elf.EM_X86_64))
	bo.PutUint32(raw[20:], 1)
	bo.PutUint64(raw[40:], 0x100)

	bo.PutUint16(raw[52:], 64)
	bo.PutUint16(raw[58:], 64)
	bo.PutUint16(raw[60:], 3)
	bo.PutUint16(raw[62:], 2)

	copy(raw[0x80:], []byte{
		0x55, 0x89, 0xe5, 0xc3,
	})

	names := []byte("\x00.text\x00.shstrtab\x00")
	copy(raw[0x90:], names)

	textHdr := raw[0x140:]

	bo.PutUint32(textHdr[0:], 1)
	bo.PutUint32(textHdr[4:], uint32(elf.SHT_PROGBITS))
	bo.PutUint64(
		textHdr[8:],
		uint64(elf.SHF_ALLOC|elf.SHF_EXECINSTR),
	)
	bo.PutUint64(textHdr[24:], 0x80)
	bo.PutUint64(textHdr[32:], 4)
	bo.PutUint64(textHdr[48:], 1)

	strHdr := raw[0x180:]

	bo.PutUint32(strHdr[0:], 7)
	bo.PutUint32(strHdr[4:], uint32(elf.SHT_STRTAB))
	bo.PutUint64(strHdr[24:], 0x90)
	bo.PutUint64(strHdr[32:], uint64(len(names)))
	bo.PutUint64(strHdr[48:], 1)

	parsed, err := binary.Engine(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Engine(parsed)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Sections) != 1 ||
		got.Sections[0].Index != 1 ||
		len(got.Sections[0].Instructions) != 3 ||
		got.Sections[0].Instructions[0].Address != 0 ||
		got.Sections[0].Instructions[2].Flow != FlowReturn {
		t.Fatalf("ET_REL decoding failed: %+v", got)
	}
}

func TestEngineRejectsAmbiguousResult(t *testing.T) {
	if _, err := Engine(nil); err == nil {
		t.Fatal("accepted nil ELF result")
	}

	if _, err := Engine(
		&binary.ELFResult{},
	); err == nil {
		t.Fatal("accepted ELF with no source")
	}
}
