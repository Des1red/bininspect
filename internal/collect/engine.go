package collect

import (
	"fmt"

	"bininspect/internal/models"
)

func Engine() error {
	models.Knowledge = struct {
		File     string
		ELF      string
		MachO    string
		PE       string
		Unknown  string
		Programs string
		Sections string
		Symbols  string
		Dynamic  string
		Relocs   string
		Notes    string
		Security string
		Assembly string
		RawData  string
		Strings  string
		Debug    string
	}{}

	if err := CommonEngine(); err != nil {
		return err
	}

	switch {
	case models.ActiveEngines.ELF:
		return ELFEngine()

	case models.ActiveEngines.PE:
		return PEEngine()

	case models.ActiveEngines.MACH_O:
		return MachOEngine()

	case models.ActiveEngines.Unknown:
		return UnknownEngine()

	default:
		return fmt.Errorf("no active collection engine")
	}
}
