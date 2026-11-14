package analyzer

import (
	"debug/elf"
	"testing"

	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestAnalyzeELFSecurityIntegration(t *testing.T) {
	parsed := &binary.ELFResult{
		Info: binary.Info{
			Format:       binary.FormatELF,
			Architecture: binary.ArchX8664,
			Bits:         64,
		},
		Header: elf.FileHeader{
			Type: elf.ET_EXEC,
		},
		Image: &binary.Image{},
		Programs: []elf.ProgHeader{{
			Type:  elf.PT_GNU_STACK,
			Flags: elf.PF_R | elf.PF_W,
		}},
	}

	got, err := AnalyzeELF(
		parsed,
		decoder.Result{},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got.Security.NX.Status != "enabled" ||
		got.Security.PIE.Status != "disabled" {
		t.Fatalf(
			"security not integrated: %+v",
			got.Security,
		)
	}
}
