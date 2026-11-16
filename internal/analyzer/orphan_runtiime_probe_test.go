package analyzer_test

import (
	"debug/elf"
	"testing"

	"bininspect/internal/collect"
)

func TestProbeOrphanRuntimeFunction(t *testing.T) {
	const target = "/bin/ls"

	file, err := elf.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if file.Class != elf.ELFCLASS64 ||
		file.Machine != elf.EM_X86_64 {
		t.Skip("probe targets x86-64 ELF")
	}

	var arrays []*elf.Section

	for _, name := range []string{
		".preinit_array",
		".init_array",
		".fini_array",
	} {
		section := file.Section(name)
		if section == nil {
			continue
		}

		arrays = append(arrays, section)

		data, err := section.Data()
		if err != nil {
			t.Fatal(err)
		}

		t.Logf(
			"ARRAY %s: address=%#x size=%d",
			name,
			section.Addr,
			len(data),
		)

		for offset := 0; offset+8 <= len(data); offset += 8 {
			value := file.ByteOrder.Uint64(data[offset:])

			t.Logf(
				"  entry RVA=%#x raw-pointer=%#x",
				section.Addr+uint64(offset),
				value,
			)
		}
	}

	// PIE binaries may contain R_X86_64_RELATIVE
	// relocations for array entries. Their addends
	// identify the executable-relative function address.
	rela := file.Section(".rela.dyn")

	if rela != nil {
		data, err := rela.Data()
		if err != nil {
			t.Fatal(err)
		}

		for offset := 0; offset+24 <= len(data); offset += 24 {
			rOffset := file.ByteOrder.Uint64(data[offset:])
			rInfo := file.ByteOrder.Uint64(data[offset+8:])
			rAddend := int64(
				file.ByteOrder.Uint64(data[offset+16:]),
			)

			for _, section := range arrays {
				if rOffset < section.Addr ||
					rOffset >= section.Addr+section.Size {
					continue
				}

				t.Logf(
					"ARRAY RELOCATION: %s "+
						"offset=%#x type=%s addend=%#x",
					section.Name,
					rOffset,
					elf.R_X86_64(uint32(rInfo)),
					rAddend,
				)
			}
		}
	}

	result, err := collect.Engine(target)
	if err != nil {
		t.Fatal(err)
	}

	// Inspect the code around the two remaining calls.
	for gi, graph := range result.Graphs {
		if graph.Name != ".text" {
			continue
		}

		for _, fn := range result.Functions {
			if fn.Graph == gi &&
				fn.Entry >= 0x3900 &&
				fn.Entry < 0x3a00 {

				t.Logf(
					"RECOVERED: entry=%#x name=%s source=%s",
					fn.Entry,
					fn.Name,
					fn.Source,
				)
			}
		}

		for _, block := range graph.Blocks {
			if block.End <= 0x3980 ||
				block.Start >= 0x3a00 {
				continue
			}

			t.Logf(
				"BLOCK: [%#x,%#x)",
				block.Start,
				block.End,
			)

			for _, inst := range block.Instructions {
				t.Logf(
					"  %#x: %-10s operands=%+v bytes=% x",
					inst.Address,
					inst.Mnemonic,
					inst.Operands,
					inst.Bytes,
				)
			}
		}
	}
}
