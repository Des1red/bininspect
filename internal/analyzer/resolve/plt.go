package resolve

import (
	"debug/elf"
	"math"
	"strings"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

// PLTTargets maps PLT stub entry addresses to imported symbol names.
//
// Current support: x86-64 RIP-relative PLT jumps associated
// with R_X86_64_JMP_SLOT relocations.
//
// It does not execute the binary or apply relocations.
func PLTTargets(
	parsed *binary.ELFResult,
	graphs []cfg.Graph,
) map[uint64]string {
	result := make(map[uint64]string)

	if parsed != nil &&
		parsed.Info.Architecture == binary.ArchX86 {
		return pltTargetsI386(parsed, graphs)
	}

	if parsed == nil ||
		parsed.Object != nil ||
		parsed.Info.Architecture != binary.ArchX8664 {
		return result
	}

	// GOT address -> imported symbol.
	gotSymbols := make(map[uint64]string)

	tables := [][]binary.ELFRelocation{
		parsed.Metadata.Relocations,
		parsed.DynamicMetadata.Relocations,
	}

	for _, table := range tables {
		for _, rel := range table {
			if rel.Type != uint32(elf.R_X86_64_JMP_SLOT) ||
				rel.SymbolName == "" {
				continue
			}

			gotSymbols[rel.Offset] = rel.SymbolName
		}
	}

	// Find PLT indirect jumps that reference those GOT entries.
	for _, graph := range graphs {
		if graph.Name != ".plt" &&
			graph.Name != ".plt.sec" &&
			graph.Name != ".plt.got" {
			continue
		}
		// Identify Intel CET landing pads independently of CFG
		// block boundaries. A CFG block may begin with padding
		// preceding the actual PLT entry.
		endbr := make(map[uint64]bool)

		for _, block := range graph.Blocks {
			for _, inst := range block.Instructions {
				if inst.Mnemonic == "ENDBR64" &&
					inst.Size == 4 {
					endbr[inst.Address] = true
				}
			}
		}
		for _, block := range graph.Blocks {
			for _, inst := range block.Instructions {
				if inst.Flow != decoder.FlowJump ||
					!inst.Indirect ||
					len(inst.Operands) == 0 {
					continue
				}

				op := inst.Operands[0]

				if op.Kind != decoder.OperandMemory ||
					!strings.EqualFold(op.Memory.Base, "RIP") ||
					op.Memory.Index != "" {
					continue
				}

				if inst.Address >
					math.MaxUint64-uint64(inst.Size) {
					continue
				}

				next := inst.Address + uint64(inst.Size)
				disp := op.Memory.Displacement

				var got uint64

				if disp < 0 {
					if disp == math.MinInt64 ||
						uint64(-disp) > next {
						continue
					}

					got = next - uint64(-disp)
				} else {
					if uint64(disp) > math.MaxUint64-next {
						continue
					}

					got = next + uint64(disp)
				}

				if name, ok := gotSymbols[got]; ok {
					entry := block.Start

					// With CET-enabled PLT stubs, ENDBR64 marks the
					// actual callable entry. The indirect JMP normally
					// follows it immediately.
					//
					// Do not rely solely on CFG block.Start because
					// that block may also contain preceding padding.
					if inst.Address >= 4 &&
						endbr[inst.Address-4] {
						entry = inst.Address - 4
					}

					result[entry] = name
				}
			}
		}
	}

	return result
}
