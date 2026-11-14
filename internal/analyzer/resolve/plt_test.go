package resolve

import (
	"debug/elf"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestPLTTargets(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Architecture: binary.ArchX8664,
		},
		Image: &binary.Image{},
	}

	parsed.DynamicMetadata.Relocations = []binary.ELFRelocation{
		{
			Offset:     0x5000,
			Type:       uint32(elf.R_X86_64_JMP_SLOT),
			SymbolName: "strcpy@GLIBC_2.2.5",
		},
	}

	graphs := []cfg.Graph{
		{
			Name: ".plt.sec",
			Blocks: []cfg.Block{
				{
					Start: 0x1000,
					Instructions: []decoder.Instruction{
						{
							Address:  0x1004,
							Size:     6,
							Flow:     decoder.FlowJump,
							Indirect: true,
							Operands: []decoder.Operand{
								{
									Kind: decoder.OperandMemory,
									Memory: decoder.Memory{
										Base:         "RIP",
										Displacement: 0x5000 - 0x100a,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	got := PLTTargets(parsed, graphs)

	if got[0x1000] != "strcpy@GLIBC_2.2.5" {
		t.Fatalf("incorrect PLT resolution: %+v", got)
	}
}

func TestPLTEntryAfterPadding(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Architecture: binary.ArchX8664,
		},
		Image: &binary.Image{},
	}

	parsed.DynamicMetadata.Relocations = []binary.ELFRelocation{
		{
			Offset:     0x5000,
			Type:       uint32(elf.R_X86_64_JMP_SLOT),
			SymbolName: "strcpy",
		},
	}

	graphs := []cfg.Graph{
		{
			Name: ".plt.sec",
			Blocks: []cfg.Block{
				{
					Start: 0xa0a,
					Instructions: []decoder.Instruction{
						{
							Address:  0xa0a,
							Size:     6,
							Mnemonic: "NOP",
						},
						{
							Address:  0xa10,
							Size:     4,
							Mnemonic: "ENDBR64",
						},
						{
							Address:  0xa14,
							Size:     6,
							Mnemonic: "JMP",
							Flow:     decoder.FlowJump,
							Indirect: true,
							Operands: []decoder.Operand{
								{
									Kind: decoder.OperandMemory,
									Memory: decoder.Memory{
										Base:         "RIP",
										Displacement: 0x5000 - 0xa1a,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	targets := PLTTargets(parsed, graphs)

	if targets[0xa10] != "strcpy" {
		t.Fatalf(
			"expected PLT entry at 0xa10, got %+v",
			targets,
		)
	}

	if _, exists := targets[0xa0a]; exists {
		t.Fatal(
			"incorrectly mapped import to preceding padding",
		)
	}
}
