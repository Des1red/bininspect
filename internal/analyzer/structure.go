package analyzer

import (
	"strings"

	"bininspect/internal/models"
)

func Structure() models.BinaryStructure {
	k := models.Knowledge

	result := models.BinaryStructure{
		Sections: matching(
			k.Sections,
			"PROGBITS", "NOBITS", "SYMTAB",
			"DYNAMIC", "REL", "SHT_",
		),
		Segments: matching(
			k.Programs,
			"LOAD", "GNU_STACK", "GNU_RELRO",
			"INTERP", "Segment:",
		),
		Symbols: matching(
			k.Symbols,
			" FUNC ", " OBJECT ", "0x",
		),
	}

	switch models.Scope.Format {
	case "ELF":
		result.Libraries = matching(
			k.Dynamic, "(NEEDED)",
		)

	case "PE":
		result.Libraries = matching(
			k.Dynamic, "DLL Name:",
		)

	case "Mach-O":
		result.Libraries = matching(
			k.Dynamic, ".dylib", ".framework/",
		)
	}

	for _, line := range lines(k.Relocs) {
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

func Sources() map[string]models.SourceSummary {
	k := models.Knowledge

	sources := map[string]string{
		"file":     k.File,
		"elf":      k.ELF,
		"pe":       k.PE,
		"macho":    k.MachO,
		"unknown":  k.Unknown,
		"programs": k.Programs,
		"sections": k.Sections,
		"symbols":  k.Symbols,
		"dynamic":  k.Dynamic,
		"relocs":   k.Relocs,
		"notes":    k.Notes,
		"security": k.Security,
		"assembly": k.Assembly,
		"rawdata":  k.RawData,
		"strings":  k.Strings,
		"debug":    k.Debug,
	}

	result := make(map[string]models.SourceSummary)

	for name, data := range sources {
		count := 0

		if data != "" {
			count = strings.Count(data, "\n") + 1
			if strings.HasSuffix(data, "\n") {
				count--
			}
		}

		result[name] = models.SourceSummary{
			Available: strings.TrimSpace(data) != "" &&
				!strings.HasPrefix(data, "Disassembly unavailable:"),
			Lines: count,
			Bytes: len(data),
		}
	}

	return result
}
