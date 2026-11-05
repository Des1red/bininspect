package collect

import (
	"fmt"

	"bininspect/internal/models"
)

func PEEngine() error {
	collectors := []struct {
		name string
		run  func() (string, error)
		dest *string
	}{
		{"pe", PEHeaders, &models.Knowledge.PE},
		{"sections", PESections, &models.Knowledge.Sections},
		{"symbols", PESymbols, &models.Knowledge.Symbols},
		{"imports", PEImports, &models.Knowledge.Dynamic},
		{"relocations", PERelocs, &models.Knowledge.Relocs},
		{"assembly", PEAssembly, &models.Knowledge.Assembly},
		{"rawdata", PERawData, &models.Knowledge.RawData},
	}

	for _, collector := range collectors {
		data, err := collector.run()
		if err != nil {
			return fmt.Errorf("collect %s: %w", collector.name, err)
		}

		*collector.dest = data
	}

	return nil
}

func PEHeaders() (string, error) {
	return run("objdump", "-f")
}

func PESections() (string, error) {
	return run("objdump", "-h")
}

func PESymbols() (string, error) {
	return run("objdump", "-t")
}

func PEImports() (string, error) {
	return run("objdump", "-p")
}

func PERelocs() (string, error) {
	return run("objdump", "-r")
}

func PEAssembly() (string, error) {
	return run("objdump", "-d", "-M", "intel")
}

func PERawData() (string, error) {
	return run("objdump", "-s")
}
