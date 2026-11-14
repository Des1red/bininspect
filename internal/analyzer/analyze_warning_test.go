package analyzer

import (
	"debug/elf"
	"testing"

	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestAnalyzeELFDeduplicatesWarnings(t *testing.T) {
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
	}

	parsed.Validation.Warnings = []string{
		"duplicate warning",
		"independent warning",
	}
	parsed.DynamicMetadata.Warnings = []string{
		"duplicate warning",
	}
	parsed.Versions.Warnings = []string{
		"duplicate warning",
	}

	got, err := AnalyzeELF(parsed, decoder.Result{})
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, warning := range got.Warnings {
		if warning == "duplicate warning" {
			count++
		}
	}

	if count != 1 {
		t.Fatalf(
			"expected one occurrence, got %d: %v",
			count,
			got.Warnings,
		)
	}
}
