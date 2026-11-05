package internal

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"

	"bininspect/internal/models"
)

func activateEngine() {
	models.ActiveEngines = models.Engines{}
	models.Scope.Format = "unknown"

	if f, err := elf.Open(models.Scope.Target); err == nil {
		f.Close()
		models.Scope.Format = "ELF"
		models.ActiveEngines.ELF = true
		return
	}

	if f, err := pe.Open(models.Scope.Target); err == nil {
		f.Close()
		models.Scope.Format = "PE"
		models.ActiveEngines.PE = true
		return
	}

	if f, err := macho.OpenFat(models.Scope.Target); err == nil {
		f.Close()
		models.Scope.Format = "Mach-O"
		models.ActiveEngines.MACH_O = true
		return
	} else if errors.Is(err, macho.ErrNotFat) {
		if f, err := macho.Open(models.Scope.Target); err == nil {
			f.Close()
			models.Scope.Format = "Mach-O"
			models.ActiveEngines.MACH_O = true
			return
		}
	}

	models.ActiveEngines.Unknown = true
}
