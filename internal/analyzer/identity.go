package analyzer

import (
	"strings"

	"bininspect/internal/models"
)

func Identity() models.BinaryIdentity {
	k := models.Knowledge

	result := models.BinaryIdentity{
		Format:      models.Scope.Format,
		Description: strings.TrimSpace(k.File),
	}

	switch models.Scope.Format {
	case "ELF":
		result.Architecture = field(k.ELF, "Machine:")
		result.Class = field(k.ELF, "Class:")
		result.Endianness = field(k.ELF, "Data:")
		result.Type = field(k.ELF, "Type:")
		result.EntryPoint = field(k.ELF, "Entry point address:")

	case "PE":
		result.Architecture = field(k.PE, "architecture:")
		result.Type = "PE/COFF"

	case "Mach-O":
		result.Architecture = field(k.MachO, "CPU:")
		result.Type = field(k.MachO, "Type:")
	}

	return result
}
