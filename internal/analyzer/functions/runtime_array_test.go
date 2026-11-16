package functions

import (
	"bytes"
	"debug/elf"
	stdbinary "encoding/binary"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func runtimeArrayFixture(
	t *testing.T,
	data []byte,
	bits uint8,
	encoding elf.Data,
	sections []elf.SectionHeader,
) *binary.ELFResult {
	t.Helper()

	info := binary.Info{
		Format:       binary.FormatELF,
		Architecture: binary.ArchX8664,
		Bits:         bits,
		Endianness:   binary.LittleEndian,
	}

	class := elf.ELFCLASS64

	if bits == 32 {
		info.Architecture = binary.ArchX86
		class = elf.ELFCLASS32
	}

	if encoding == elf.ELFDATA2MSB {
		info.Endianness = binary.BigEndian
	}

	raw := make([]byte, 0x40+len(data))
	copy(raw[0x40:], data)

	image, err := binary.NewImage(
		bytes.NewReader(raw),
		uint64(len(raw)),
		info,
		[]binary.Region{{
			Name:        ".arrays",
			Address:     0x2000,
			MemorySize:  uint64(len(data)),
			FileOffset:  0x40,
			FileSize:    uint64(len(data)),
			Permissions: binary.PermRead,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	return &binary.ELFResult{
		Info: info,
		Header: elf.FileHeader{
			Class: class,
			Data:  encoding,
			Type:  elf.ET_DYN,
		},
		Image:    image,
		Sections: sections,
	}
}

func TestRuntimeArrayEntriesAndRecovery(t *testing.T) {
	data := make([]byte, 40)

	stdbinary.LittleEndian.PutUint64(data[0:], 0x1000)
	stdbinary.LittleEndian.PutUint64(data[8:], 0x1001)
	stdbinary.LittleEndian.PutUint64(data[16:], 0x1001)
	stdbinary.LittleEndian.PutUint64(data[24:], 0x1002)

	parsed := runtimeArrayFixture(
		t,
		data,
		64,
		elf.ELFDATA2LSB,
		[]elf.SectionHeader{
			{Name: ".preinit_array", Addr: 0x2000, Size: 8},
			{Name: ".init_array", Addr: 0x2008, Size: 16},
			{Name: ".fini_array", Addr: 0x2018, Size: 16},
		},
	)

	want := map[uint64]string{
		0x1000: "preinit-array",
		0x1001: "init-array",
		0x1002: "fini-array",
	}

	entries := RuntimeArrayEntries(parsed)

	if len(entries) != len(want) {
		t.Fatalf("entries=%+v, want %d", entries, len(want))
	}

	for _, entry := range entries {
		if want[entry.Address] != entry.Source {
			t.Fatalf("unexpected runtime entry: %+v", entry)
		}
	}

	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 7,
			Name:  ".text",
			Instructions: []decoder.Instruction{
				{Address: 0x1000, Size: 1, Mnemonic: "NOP"},
				{Address: 0x1001, Size: 1, Mnemonic: "NOP"},
				{
					Address:   0x1002,
					Size:      1,
					Mnemonic:  "CALL",
					Flow:      decoder.FlowCall,
					HasTarget: true,
					Target:    0x5000,
				},
				{
					Address:  0x1003,
					Size:     1,
					Mnemonic: "RET",
					Flow:     decoder.FlowReturn,
				},
			},
		}},
	}

	leaders := Leaders(parsed, decoded)

	for address := range want {
		if !leaders[0][address] {
			t.Fatalf("missing runtime leader %#x", address)
		}
	}

	graphs, err := cfg.BuildWithLeaders(decoded, leaders)
	if err != nil {
		t.Fatal(err)
	}

	recovered := Recover(parsed, graphs)
	found := make(map[uint64]Function)

	for _, fn := range recovered {
		found[fn.Entry] = fn
	}

	for address, source := range want {
		fn, ok := found[address]
		if !ok {
			t.Fatalf("missing recovered function %#x", address)
		}
		if fn.Source != source {
			t.Fatalf(
				"function %#x source=%q, want %q",
				address, fn.Source, source,
			)
		}
	}

	fini := found[0x1002]

	if len(fini.Calls) != 1 ||
		fini.Calls[0].Address != 0x1002 {
		t.Fatalf("finalizer calls=%+v", fini.Calls)
	}
}

func TestRuntimeArray32BitBigEndian(t *testing.T) {
	data := make([]byte, 8)

	stdbinary.BigEndian.PutUint32(data[0:], 0x1100)
	stdbinary.BigEndian.PutUint32(data[4:], 0x1200)

	parsed := runtimeArrayFixture(
		t,
		data,
		32,
		elf.ELFDATA2MSB,
		[]elf.SectionHeader{{
			Name: ".fini_array",
			Addr: 0x2000,
			Size: 8,
		}},
	)

	entries := RuntimeArrayEntries(parsed)

	if len(entries) != 2 ||
		entries[0].Address != 0x1100 ||
		entries[1].Address != 0x1200 {
		t.Fatalf("unexpected 32-bit entries: %+v", entries)
	}
}

func TestRuntimeArrayRejectsMalformedSections(t *testing.T) {
	data := make([]byte, 16)
	stdbinary.LittleEndian.PutUint64(data, 0x1000)

	parsed := runtimeArrayFixture(
		t,
		data,
		64,
		elf.ELFDATA2LSB,
		[]elf.SectionHeader{{
			Name: ".init_array",
			Addr: 0x2000,
			Size: 8,
		}},
	)

	tests := []struct {
		name   string
		mutate func(*binary.ELFResult)
	}{
		{
			name: "relocatable",
			mutate: func(p *binary.ELFResult) {
				p.Header.Type = elf.ET_REL
			},
		},
		{
			name: "invalid width",
			mutate: func(p *binary.ELFResult) {
				p.Sections[0].Size = 7
			},
		},
		{
			name: "unmapped array",
			mutate: func(p *binary.ELFResult) {
				p.Sections[0].Addr = 0x4000
			},
		},
		{
			name: "oversized array",
			mutate: func(p *binary.ELFResult) {
				p.Sections[0].Size = (1 << 20) + 8
			},
		},
		{
			name: "missing image",
			mutate: func(p *binary.ELFResult) {
				p.Image = nil
			},
		},
		{
			name: "invalid endian",
			mutate: func(p *binary.ELFResult) {
				p.Header.Data = elf.ELFDATANONE
			},
		},
	}

	if got := RuntimeArrayEntries(nil); len(got) != 0 {
		t.Fatalf("nil ELF returned entries: %+v", got)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copyResult := *parsed
			copyResult.Sections = append(
				[]elf.SectionHeader(nil),
				parsed.Sections...,
			)

			tt.mutate(&copyResult)

			if got := RuntimeArrayEntries(&copyResult); len(got) != 0 {
				t.Fatalf("malformed array accepted: %+v", got)
			}
		})
	}
}
