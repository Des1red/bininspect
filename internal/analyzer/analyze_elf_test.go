package analyzer

import (
	"debug/elf"
	"testing"

	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestAnalyzeELFStructuredInput(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Format: binary.FormatELF,
			Bits:   64,
		},
		Header: elf.FileHeader{
			Type: elf.ET_EXEC,
		},
		Image: &binary.Image{},
		Programs: []elf.ProgHeader{
			{Type: elf.PT_LOAD},
		},
		Sections: []elf.SectionHeader{
			{Type: elf.SHT_PROGBITS},
		},
		Dynamic: binary.ELFDynamicInfo{
			Needed: []string{"libc.so.6"},
		},
	}

	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 0,
			Name:  ".text",
			Instructions: []decoder.Instruction{
				{Address: 0x1000, Size: 1},
				{
					Address: 0x1001,
					Size:    1,
					Flow:    decoder.FlowReturn,
				},
			},
		}},
	}

	got, err := AnalyzeELF(parsed, decoded)
	if err != nil {
		t.Fatal(err)
	}

	if got.Info.Bits != 64 ||
		got.ELFType != elf.ET_EXEC ||
		got.Structure.Dependencies != 1 ||
		got.Assembly.CandidateInstructions != 2 ||
		got.Assembly.Returns != 1 ||
		len(got.Graphs) != 1 ||
		len(got.Graphs[0].Blocks) != 1 {
		t.Fatalf("unexpected analysis: %+v", got)
	}
}

func TestAnalyzeELFRejectsInvalidInput(t *testing.T) {
	if _, err := AnalyzeELF(
		nil, decoder.Result{},
	); err == nil {
		t.Fatal("accepted nil input")
	}

	if _, err := AnalyzeELF(
		&binary.ELFResult{},
		decoder.Result{},
	); err == nil {
		t.Fatal("accepted empty ELF input")
	}
}
