package resolve

import (
	"debug/elf"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestI386PLTImportResolution(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Format:       binary.FormatELF,
			Architecture: binary.ArchX86,
			Bits:         32,
		},
		Header: elf.FileHeader{
			Class: elf.ELFCLASS32,
			Type:  elf.ET_EXEC,
		},
		Metadata: binary.ELFMetadata{
			Relocations: []binary.ELFRelocation{
				{
					Offset:     0x8049630,
					Type:       uint32(elf.R_386_JMP_SLOT),
					SymbolName: "gets",
				},
				{
					Offset:     0x8049638,
					Type:       uint32(elf.R_386_JMP_SLOT),
					SymbolName: "puts",
				},
			},
		},
	}

	makeBlock := func(
		address uint64,
		slot uint32,
	) cfg.Block {
		return cfg.Block{
			Start: address,
			End:   address + 6,
			Instructions: []decoder.Instruction{{
				Address:  address,
				Size:     6,
				Mnemonic: "JMP",
				Flow:     decoder.FlowJump,
				Indirect: true,
				Bytes: []byte{
					0xff, 0x25,
					byte(slot),
					byte(slot >> 8),
					byte(slot >> 16),
					byte(slot >> 24),
				},
				Operands: []decoder.Operand{{
					Kind: decoder.OperandMemory,
					Memory: decoder.Memory{
						Displacement: int64(slot),
						SizeBytes:    4,
					},
				}},
			}},
		}
	}

	graphs := []cfg.Graph{{
		Name: ".plt",
		Blocks: []cfg.Block{
			makeBlock(0x804830c, 0x8049630),
			makeBlock(0x804832c, 0x8049638),
			makeBlock(0x804834c, 0x8049640),
		},
	}}

	targets := PLTTargets(parsed, graphs)

	if targets[0x804830c] != "gets" {
		t.Fatalf(
			"gets PLT unresolved: %+v",
			targets,
		)
	}

	if targets[0x804832c] != "puts" {
		t.Fatalf(
			"puts PLT unresolved: %+v",
			targets,
		)
	}

	if _, exists := targets[0x804834c]; exists {
		t.Fatal("accepted PLT entry without relocation")
	}

	if len(targets) != 2 {
		t.Fatalf("unexpected PLT targets: %+v", targets)
	}
}
