package identity

import (
	"strings"

	"bininspect/internal/analyzer/shared"
	"bininspect/internal/models"
)

func Analyze() models.BinaryIdentity {
	k := models.Knowledge

	result := models.BinaryIdentity{
		Format:      models.Scope.Format,
		Description: strings.TrimSpace(k.File),
	}

	switch models.Scope.Format {
	case "ELF":
		result.Architecture = shared.Field(k.ELF, "Machine:")
		result.Class = shared.Field(k.ELF, "Class:")
		result.Endianness = shared.Field(k.ELF, "Data:")
		result.Type = shared.Field(k.ELF, "Type:")
		result.EntryPoint = shared.Field(k.ELF, "Entry point address:")

	case "PE":
		result.Architecture = shared.Field(k.PE, "architecture:")
		result.Type = "PE/COFF"

	case "Mach-O":
		result.Architecture = shared.Field(k.MachO, "CPU:")
		result.Type = shared.Field(k.MachO, "Type:")
	}

	return result
}
