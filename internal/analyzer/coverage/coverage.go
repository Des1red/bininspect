package coverage

import (
	"strings"

	"bininspect/internal/models"
)

func Analyze() map[string]models.SourceSummary {
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
