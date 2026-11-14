package analyzer

import (
	"debug/elf"
	"testing"

	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestAnalyzeELFFindingsIntegration(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Format:       binary.FormatELF,
			Architecture: binary.ArchX8664,
			Bits:         64,
			Entry:        0x1000,
		},
		Header: elf.FileHeader{
			Type: elf.ET_EXEC,
		},
		Image: &binary.Image{},
		Programs: []elf.ProgHeader{{
			Type:  elf.PT_GNU_STACK,
			Flags: elf.PF_R | elf.PF_W | elf.PF_X,
		}},
	}

	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index: 1,
			Name:  ".text",
			Instructions: []decoder.Instruction{
				{
					Address:  0x1000,
					Size:     5,
					Mnemonic: "CALL",
					Flow:     decoder.FlowCall,
					Relocations: []decoder.RelocationReference{{
						SymbolName: "gets",
					}},
				},
				{
					Address:  0x1005,
					Size:     1,
					Mnemonic: "RET",
					Flow:     decoder.FlowReturn,
				},
			},
		}},
	}

	got, err := AnalyzeELF(parsed, decoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Functions) == 0 ||
		len(got.DataFlow.Calls) != 1 ||
		got.Security.NX.Status != "disabled" {
		t.Fatalf("pipeline incomplete: %+v", got)
	}

	hasAPI, hasNX := false, false

	for _, finding := range got.Findings {
		if finding.ID == "API-gets-1-1000" {
			hasAPI = true
		}
		if finding.ID == "SEC-EXECSTACK" {
			hasNX = true
		}
	}

	if !hasAPI || !hasNX {
		t.Fatalf(
			"findings not integrated: %+v",
			got.Findings,
		)
	}
}
