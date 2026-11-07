package binary

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"
)

func dynamicMetadataFixture() []byte {
	raw := make([]byte, 0x800)
	copy(raw, "\x7fELF")

	raw[4] = 2
	raw[5] = 1
	raw[6] = 1

	bo := binary.LittleEndian

	bo.PutUint16(raw[16:], uint16(elf.ET_DYN))
	bo.PutUint16(raw[18:], uint16(elf.EM_X86_64))
	bo.PutUint32(raw[20:], 1)
	bo.PutUint64(raw[24:], 0x400100)
	bo.PutUint64(raw[32:], 64)
	bo.PutUint16(raw[52:], 64)
	bo.PutUint16(raw[54:], 56)
	bo.PutUint16(raw[56:], 2)

	load := raw[64:]
	bo.PutUint32(load[0:], uint32(elf.PT_LOAD))
	bo.PutUint32(load[4:], uint32(elf.PF_R|elf.PF_X))
	bo.PutUint64(load[8:], 0x100)
	bo.PutUint64(load[16:], 0x400100)
	bo.PutUint64(load[32:], 0x700)
	bo.PutUint64(load[40:], 0x700)
	bo.PutUint64(load[48:], 0x100)

	dynamic := raw[120:]
	bo.PutUint32(dynamic[0:], uint32(elf.PT_DYNAMIC))
	bo.PutUint32(dynamic[4:], uint32(elf.PF_R))
	bo.PutUint64(dynamic[8:], 0x180)
	bo.PutUint64(dynamic[16:], 0x400180)
	bo.PutUint64(dynamic[32:], 15*16)
	bo.PutUint64(dynamic[40:], 15*16)
	bo.PutUint64(dynamic[48:], 8)

	copy(raw[0x330:], []byte("\x00puts\x00foo\x00"))

	// SysV hash table: one bucket and three symbols.
	bo.PutUint32(raw[0x3c0:], 1)
	bo.PutUint32(raw[0x3c4:], 3)
	bo.PutUint32(raw[0x3c8:], 1)
	bo.PutUint32(raw[0x3cc:], 0)
	bo.PutUint32(raw[0x3d0:], 2)
	bo.PutUint32(raw[0x3d4:], 0)

	// Dynamic symbol 1: puts.
	bo.PutUint32(raw[0x418:], 1)
	raw[0x41c] = 0x12

	// Dynamic symbol 2: foo.
	bo.PutUint32(raw[0x430:], 6)
	raw[0x434] = 0x12

	// Regular RELA relocation.
	bo.PutUint64(raw[0x500:], 0x400600)
	bo.PutUint64(raw[0x508:], (uint64(2)<<32)|7)
	bo.PutUint64(raw[0x510:], ^uint64(3))

	// PLT relocation.
	bo.PutUint64(raw[0x518:], 0x400608)
	bo.PutUint64(raw[0x520:], (uint64(1)<<32)|7)

	// RELR base followed by a bitmap.
	bo.PutUint64(raw[0x530:], 0x400620)
	bo.PutUint64(raw[0x538:], 0b1011)

	tags := [][2]uint64{
		{uint64(elf.DT_STRTAB), 0x400330},
		{uint64(elf.DT_STRSZ), 10},
		{uint64(elf.DT_SYMTAB), 0x400400},
		{uint64(elf.DT_SYMENT), 24},
		{uint64(elf.DT_HASH), 0x4003c0},
		{uint64(elf.DT_RELA), 0x400500},
		{uint64(elf.DT_RELASZ), 24},
		{uint64(elf.DT_RELAENT), 24},
		{uint64(elf.DT_JMPREL), 0x400518},
		{uint64(elf.DT_PLTRELSZ), 24},
		{uint64(elf.DT_PLTREL), uint64(elf.DT_RELA)},
		{uint64(dynRelr), 0x400530},
		{uint64(dynRelrSz), 16},
		{uint64(dynRelrEnt), 8},
		{0, 0},
	}

	for i, entry := range tags {
		pos := 0x180 + i*16
		bo.PutUint64(raw[pos:], entry[0])
		bo.PutUint64(raw[pos+8:], entry[1])
	}

	return raw
}

func TestDynamicMetadataSynthetic(t *testing.T) {
	raw := dynamicMetadataFixture()

	result, err := ParseELFDynamicMetadata(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Symbols) != 3 ||
		len(result.Relocations) != 5 ||
		result.Relocations[0].SymbolName != "foo" ||
		result.Relocations[1].SymbolName != "puts" ||
		!result.SymbolCountComplete {
		t.Fatalf("unexpected dynamic metadata: %+v", result)
	}
}

func TestDynamicMetadataGNUHash(t *testing.T) {
	raw := dynamicMetadataFixture()
	bo := binary.LittleEndian

	// Replace DT_HASH with DT_GNU_HASH.
	bo.PutUint64(
		raw[0x180+4*16:],
		uint64(elf.DT_GNU_HASH),
	)

	bo.PutUint32(raw[0x3c0:], 1)
	bo.PutUint32(raw[0x3c4:], 1)
	bo.PutUint32(raw[0x3c8:], 1)
	bo.PutUint32(raw[0x3cc:], 5)

	bo.PutUint64(raw[0x3d0:], 0)
	bo.PutUint32(raw[0x3d8:], 1)
	bo.PutUint32(raw[0x3dc:], 2)
	bo.PutUint32(raw[0x3e0:], 3)

	result, err := ParseELFDynamicMetadata(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Symbols) != 3 ||
		result.SymbolCountSource != "DT_GNU_HASH" ||
		result.SymbolCountComplete {
		t.Fatalf("unexpected GNU hash result: %+v", result)
	}
}

func TestDynamicMetadataMalformed(t *testing.T) {
	tests := []struct {
		name   string
		modify func([]byte)
	}{
		{
			"invalid-hash-count",
			func(p []byte) {
				binary.LittleEndian.PutUint32(p[0x3c4:], 0)
			},
		},
		{
			"missing-string-size",
			func(p []byte) {
				binary.LittleEndian.PutUint64(
					p[0x180+16:], 0x1111,
				)
			},
		},
		{
			"invalid-relocation-symbol",
			func(p []byte) {
				binary.LittleEndian.PutUint64(
					p[0x508:],
					(uint64(88)<<32)|7,
				)
			},
		},
		{
			"relr-without-base",
			func(p []byte) {
				binary.LittleEndian.PutUint64(p[0x530:], 1)
			},
		},
		{
			"invalid-plt-encoding",
			func(p []byte) {
				binary.LittleEndian.PutUint64(
					p[0x180+10*16+8:], 21,
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := dynamicMetadataFixture()
			tt.modify(raw)

			_, err := ParseELFDynamicMetadata(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)

			if err == nil {
				t.Fatal("accepted malformed dynamic metadata")
			}
		})
	}
}

func TestDynamicMetadataRealFiles(t *testing.T) {
	for _, path := range []string{
		"/bin/ls",
		"/bin/bash",
		"/usr/bin/true",
	} {
		t.Run(path, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Skip(err)
			}

			original, err := ParseELFDynamicMetadata(
				bytes.NewReader(raw),
				uint64(len(raw)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if len(original.Symbols) == 0 ||
				len(original.Relocations) == 0 {
				t.Fatal("expected dynamic symbols and relocations")
			}

			file, err := elf.NewFile(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}

			sectionless := append([]byte(nil), raw...)

			var ranges [][2]int

			if file.Class == elf.ELFCLASS64 {
				ranges = [][2]int{
					{40, 48},
					{60, 62},
					{62, 64},
				}
			} else {
				ranges = [][2]int{
					{32, 36},
					{48, 50},
					{50, 52},
				}
			}

			for _, bounds := range ranges {
				for i := bounds[0]; i < bounds[1]; i++ {
					sectionless[i] = 0
				}
			}

			result, err := ParseELFDynamicMetadata(
				bytes.NewReader(sectionless),
				uint64(len(sectionless)),
			)
			if err != nil {
				t.Fatal(err)
			}

			if len(original.Symbols) != len(result.Symbols) ||
				len(original.Relocations) != len(result.Relocations) {
				t.Fatalf(
					"sectionless metadata changed: symbols %d/%d, relocations %d/%d",
					len(original.Symbols),
					len(result.Symbols),
					len(original.Relocations),
					len(result.Relocations),
				)
			}
		})
	}
}

func TestDynamicMetadataELF32REL(t *testing.T) {
	raw := make([]byte, 0x700)
	bo := binary.LittleEndian

	copy(raw, "\x7fELF")
	raw[4] = 1
	raw[5] = 1
	raw[6] = 1

	bo.PutUint16(raw[16:], uint16(elf.ET_DYN))
	bo.PutUint16(raw[18:], uint16(elf.EM_386))
	bo.PutUint32(raw[20:], 1)
	bo.PutUint32(raw[24:], 0x1000)
	bo.PutUint32(raw[28:], 52)
	bo.PutUint16(raw[40:], 52)
	bo.PutUint16(raw[42:], 32)
	bo.PutUint16(raw[44:], 2)

	load := raw[52:]
	bo.PutUint32(load[0:], uint32(elf.PT_LOAD))
	bo.PutUint32(load[4:], 0x100)
	bo.PutUint32(load[8:], 0x1000)
	bo.PutUint32(load[16:], 0x600)
	bo.PutUint32(load[20:], 0x600)
	bo.PutUint32(load[24:], uint32(elf.PF_R|elf.PF_X))
	bo.PutUint32(load[28:], 0x100)

	dynamic := raw[84:]
	bo.PutUint32(dynamic[0:], uint32(elf.PT_DYNAMIC))
	bo.PutUint32(dynamic[4:], 0x180)
	bo.PutUint32(dynamic[8:], 0x1080)
	bo.PutUint32(dynamic[16:], 8*9)
	bo.PutUint32(dynamic[20:], 8*9)
	bo.PutUint32(dynamic[24:], uint32(elf.PF_R))
	bo.PutUint32(dynamic[28:], 4)

	// SysV hash table with the null symbol.
	bo.PutUint32(raw[0x300:], 1)
	bo.PutUint32(raw[0x304:], 1)

	tags := [][2]uint32{
		{uint32(elf.DT_STRTAB), 0x1280},
		{uint32(elf.DT_STRSZ), 1},
		{uint32(elf.DT_SYMTAB), 0x1300},
		{uint32(elf.DT_SYMENT), 16},
		{uint32(elf.DT_HASH), 0x1200},
		{uint32(elf.DT_REL), 0x1400},
		{uint32(elf.DT_RELSZ), 8},
		{uint32(elf.DT_RELENT), 8},
		{0, 0},
	}

	for i, entry := range tags {
		pos := 0x180 + i*8
		bo.PutUint32(raw[pos:], entry[0])
		bo.PutUint32(raw[pos+4:], entry[1])
	}

	bo.PutUint32(raw[0x500:], 0x1010)
	bo.PutUint32(raw[0x504:], 8)

	result, err := ParseELFDynamicMetadata(
		bytes.NewReader(raw),
		uint64(len(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Symbols) != 1 ||
		len(result.Relocations) != 1 ||
		result.Relocations[0].Encoding != "REL" ||
		result.Relocations[0].HasAddend {
		t.Fatalf("unexpected ELF32 REL metadata: %+v", result)
	}
}
