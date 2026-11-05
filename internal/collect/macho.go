package collect

import (
	"debug/macho"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"bininspect/internal/models"
)

type MachOData struct {
	Header   string
	Programs string
	Sections string
	Symbols  string
	Dynamic  string
	Relocs   string
	Security string
	Assembly string
	RawData  string
	Debug    string
}

func MachOEngine() error {
	data, err := MachO()
	if err != nil {
		return err
	}

	models.Knowledge.MachO = data.Header
	models.Knowledge.Programs = data.Programs
	models.Knowledge.Sections = data.Sections
	models.Knowledge.Symbols = data.Symbols
	models.Knowledge.Dynamic = data.Dynamic
	models.Knowledge.Relocs = data.Relocs
	models.Knowledge.Security = data.Security
	models.Knowledge.Assembly = data.Assembly
	models.Knowledge.RawData = data.RawData
	models.Knowledge.Debug = data.Debug

	return nil
}

func MachO() (MachOData, error) {
	var data MachOData
	path := models.Scope.Target

	fat, err := macho.OpenFat(path)

	switch {
	case err == nil:
		defer fat.Close()

		for _, arch := range fat.Arches {
			inspectMachO(arch.File, &data)
		}

	case errors.Is(err, macho.ErrNotFat):
		f, err := macho.Open(path)
		if err != nil {
			return data, err
		}
		defer f.Close()

		inspectMachO(f, &data)

	default:
		return data, err
	}

	data.RawData, err = preview(path)
	if err != nil {
		return data, err
	}

	if _, err := exec.LookPath("llvm-objdump"); err == nil {
		data.Assembly, err = run(
			"llvm-objdump",
			"--macho",
			"--disassemble",
		)
		if err != nil {
			data.Assembly = fmt.Sprintf(
				"Disassembly unavailable: %v", err,
			)
		}
	} else {
		data.Assembly = "Disassembly unavailable: llvm-objdump not installed"
	}

	return data, nil
}

func inspectMachO(f *macho.File, data *MachOData) {
	data.Header += fmt.Sprintf(
		"CPU: %s\nType: %s\nMagic: 0x%x\nFlags: 0x%x\nLoad commands: %d\n\n",
		f.Cpu, f.Type, f.Magic, f.Flags, f.Ncmd,
	)

	for _, load := range f.Loads {
		if seg, ok := load.(*macho.Segment); ok {
			data.Programs += fmt.Sprintf(
				"Segment: %s Address: 0x%x Size: 0x%x Protection: 0x%x\n",
				seg.Name, seg.Addr, seg.Memsz, seg.Prot,
			)
		}
	}

	for _, section := range f.Sections {
		data.Sections += fmt.Sprintf(
			"%s/%s Address: 0x%x Size: %d Offset: %d\n",
			section.Seg, section.Name,
			section.Addr, section.Size, section.Offset,
		)

		for _, reloc := range section.Relocs {
			data.Relocs += fmt.Sprintf(
				"%s/%s Address: 0x%x Type: %d Value: %d PC-relative: %t\n",
				section.Seg, section.Name,
				reloc.Addr, reloc.Type, reloc.Value, reloc.Pcrel,
			)
		}
	}

	if f.Symtab != nil {
		for _, symbol := range f.Symtab.Syms {
			data.Symbols += fmt.Sprintf(
				"0x%x %s\n", symbol.Value, symbol.Name,
			)
		}
	}

	libs, err := f.ImportedLibraries()
	if err == nil {
		data.Dynamic += "Libraries:\n" + strings.Join(libs, "\n") + "\n"
	}

	if f.Dysymtab != nil && f.Symtab != nil {
		imports, err := f.ImportedSymbols()
		if err == nil {
			data.Dynamic += "Imported symbols:\n" +
				strings.Join(imports, "\n") + "\n"
		}
	}

	data.Security += fmt.Sprintf(
		"CPU: %s\nPIE flag: %t\nAllow stack execution flag: %t\n\n",
		f.Cpu,
		f.Flags&macho.FlagPIE != 0,
		f.Flags&macho.FlagAllowStackExecution != 0,
	)

	if _, err := f.DWARF(); err == nil {
		data.Debug += fmt.Sprintf(
			"CPU %s: DWARF data available\n", f.Cpu,
		)
	} else {
		data.Debug += fmt.Sprintf(
			"CPU %s: DWARF unavailable: %v\n", f.Cpu, err,
		)
	}
}
