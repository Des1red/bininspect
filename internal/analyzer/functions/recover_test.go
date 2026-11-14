package functions

import (
	"debug/elf"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestRecoverNamedFunctions(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Format: binary.FormatELF,
			Entry:  0x1000,
		},
		Header: elf.FileHeader{
			Type: elf.ET_EXEC,
		},
		Image: &binary.Image{},
		Metadata: binary.ELFMetadata{
			Symbols: []binary.ELFSymbol{
				{
					Name:         "main",
					Value:        0x1000,
					Type:         elf.STT_FUNC,
					SectionIndex: 1,
				},
				{
					Name:         "helper",
					Value:        0x1010,
					Type:         elf.STT_FUNC,
					SectionIndex: 1,
				},
			},
		},
	}

	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 1,
			Name:  ".text",
			Instructions: []decoder.Instruction{
				{
					Address:   0x1000,
					Size:      5,
					Flow:      decoder.FlowCall,
					Target:    0x1010,
					HasTarget: true,
				},
				{
					Address: 0x1005,
					Size:    1,
					Flow:    decoder.FlowReturn,
				},
				{
					Address: 0x1010,
					Size:    1,
					Flow:    decoder.FlowReturn,
				},
			},
		}},
	}

	graphs, err := cfg.BuildWithLeaders(
		decoded,
		Leaders(parsed, decoded),
	)
	if err != nil {
		t.Fatal(err)
	}

	got := Recover(parsed, graphs)

	if len(got) != 2 {
		t.Fatalf("expected 2 functions, got %d: %+v", len(got), got)
	}

	if got[0].Name != "main" ||
		got[0].Entry != 0x1000 ||
		got[0].Instructions != 2 ||
		len(got[0].Calls) != 1 {
		t.Fatalf("incorrect main: %+v", got[0])
	}

	if got[1].Name != "helper" ||
		got[1].Entry != 0x1010 ||
		got[1].Instructions != 1 {
		t.Fatalf("incorrect helper: %+v", got[1])
	}
}
