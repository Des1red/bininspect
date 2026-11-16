package resolve

import (
	"debug/elf"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

// pltTargetsI386 maps ELF32 i386 PLT entry addresses
// to imported symbol names using GOT relocations.
//
// Supported stub pattern:
//
//	FF 25 xx xx xx xx    JMP DWORD PTR [absolute GOT slot]
func pltTargetsI386(
	parsed *binary.ELFResult,
	graphs []cfg.Graph,
) map[uint64]string {
	out := make(map[uint64]string)

	if parsed == nil ||
		parsed.Info.Architecture != binary.ArchX86 ||
		parsed.Header.Type == elf.ET_REL {
		return out
	}

	slots := make(map[uint64]string)
	ambiguous := make(map[uint64]bool)

	addRelocations := func(
		relocations []binary.ELFRelocation,
	) {
		for _, rel := range relocations {
			if rel.Type != uint32(elf.R_386_JMP_SLOT) ||
				rel.Offset > 0xffffffff {
				continue
			}

			name := rel.SymbolName

			if name == "" {
				for _, sym := range parsed.DynamicMetadata.Symbols {
					if sym.Index == rel.SymbolIndex {
						name = sym.Name
						break
					}
				}
			}

			if name == "" {
				continue
			}

			if previous, exists := slots[rel.Offset]; exists &&
				previous != name {
				ambiguous[rel.Offset] = true
			}

			slots[rel.Offset] = name
		}
	}

	addRelocations(parsed.Metadata.Relocations)
	addRelocations(parsed.DynamicMetadata.Relocations)

	for _, graph := range graphs {
		if graph.Name != ".plt" &&
			graph.Name != ".plt.sec" {
			continue
		}

		for _, block := range graph.Blocks {
			if len(block.Instructions) == 0 {
				continue
			}

			inst := block.Instructions[0]

			if inst.Address != block.Start ||
				inst.Mnemonic != "JMP" ||
				!inst.Indirect ||
				len(inst.Operands) != 1 {
				continue
			}

			// Require the exact i386 absolute-memory
			// indirect JMP encoding.
			if len(inst.Bytes) != 6 ||
				inst.Bytes[0] != 0xff ||
				inst.Bytes[1] != 0x25 {
				continue
			}

			op := inst.Operands[0]

			if op.Kind != decoder.OperandMemory ||
				op.Memory.Base != "" ||
				op.Memory.Index != "" {
				continue
			}

			if op.Memory.SizeBytes != 0 &&
				op.Memory.SizeBytes != 4 {
				continue
			}

			// Displacements may be represented as signed
			// integers by the instruction decoder.
			slot := uint64(uint32(op.Memory.Displacement))

			if ambiguous[slot] {
				continue
			}

			if name := slots[slot]; name != "" {
				out[block.Start] = name
			}
		}
	}

	return out
}
