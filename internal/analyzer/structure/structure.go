package structure

import (
	"strings"

	"bininspect/internal/analyzer/shared"
	"bininspect/internal/models"
)

func Analyze() models.BinaryStructure {
	k := models.Knowledge

	result := models.BinaryStructure{
		Sections: shared.Matching(
			k.Sections,
			"PROGBITS", "NOBITS", "SYMTAB",
			"DYNAMIC", "REL", "SHT_",
		),
		Segments: shared.Matching(
			k.Programs,
			"LOAD", "GNU_STACK", "GNU_RELRO",
			"INTERP", "Segment:",
		),
		Symbols: shared.Matching(
			k.Symbols,
			" FUNC ", " OBJECT ", "0x",
		),
	}

	switch models.Scope.Format {
	case "ELF":
		result.Libraries = shared.Matching(
			k.Dynamic, "(NEEDED)",
		)

	case "PE":
		result.Libraries = shared.Matching(
			k.Dynamic, "DLL Name:",
		)

	case "Mach-O":
		result.Libraries = shared.Matching(
			k.Dynamic, ".dylib", ".framework/",
		)
	}

	for _, line := range shared.Lines(k.Relocs) {
		if strings.Contains(line, "R_386_") ||
			strings.Contains(line, "R_X86_64_") ||
			strings.Contains(line, "R_AARCH64_") ||
			strings.Contains(line, "IMAGE_REL_") ||
			strings.Contains(line, "Address:") {
			result.Relocations++
		}
	}

	result.DebugInfo = strings.Contains(
		k.Debug, "DWARF data available",
	) || strings.Contains(k.Debug, "Compilation Unit @ offset")

	return result
}
