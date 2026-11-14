package resolve_test

import (
	"debug/elf"
	"os"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/functions"
	"bininspect/internal/analyzer/resolve"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestProbeHostPLT(t *testing.T) {
	f, err := os.Open("/bin/ls")
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := binary.Engine(f, uint64(info.Size()))
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := decoder.Engine(parsed)
	if err != nil {
		t.Fatal(err)
	}

	graphs, err := cfg.BuildWithLeaders(
		decoded,
		functions.Leaders(parsed, decoded),
	)
	if err != nil {
		t.Fatal(err)
	}

	slots, named := 0, 0

	for _, rel := range parsed.DynamicMetadata.Relocations {
		if rel.Type == uint32(elf.R_X86_64_JMP_SLOT) {
			slots++
			if rel.SymbolName != "" {
				named++
			}
		}
	}

	targets := resolve.PLTTargets(parsed, graphs)

	t.Logf(
		"JUMP_SLOT relocations=%d, named=%d, resolved PLT entries=%d",
		slots,
		named,
		len(targets),
	)

	for _, address := range []uint64{
		0xe60,
		0xb30,
		0xbb0,
		0xc70,
	} {
		t.Logf(
			"PLT target %#x: %q",
			address,
			targets[address],
		)
	}

	printed := 0

	for _, graph := range graphs {
		if graph.Name != ".plt" &&
			graph.Name != ".plt.sec" {
			continue
		}

		for _, block := range graph.Blocks {
			for _, inst := range block.Instructions {
				if inst.Flow != decoder.FlowJump ||
					!inst.Indirect {
					continue
				}

				if printed >= 6 {
					return
				}

				t.Logf(
					"%s block=%#x jump=%#x operands=%+v",
					graph.Name,
					block.Start,
					inst.Address,
					inst.Operands,
				)

				printed++
			}
		}
	}
}
