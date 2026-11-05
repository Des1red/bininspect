package collect

import (
	"bininspect/internal/models"
	"fmt"
)

func ELFEngine() error {
	collectors := []struct {
		name string
		run  func() (string, error)
		dest *string
	}{
		{"elf", ELF, &models.Knowledge.ELF},
		{"programs", Programs, &models.Knowledge.Programs},
		{"sections", Sections, &models.Knowledge.Sections},
		{"symbols", Symbols, &models.Knowledge.Symbols},
		{"dynamic", Dynamic, &models.Knowledge.Dynamic},
		{"relocs", Relocs, &models.Knowledge.Relocs},
		{"notes", Notes, &models.Knowledge.Notes},
		{"security", Security, &models.Knowledge.Security},
		{"assembly", Assembly, &models.Knowledge.Assembly},
		{"rawdata", RawData, &models.Knowledge.RawData},
		{"debug", Debug, &models.Knowledge.Debug},
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

func ELF() (string, error) {
	return run("readelf", "-h", "-W")
}

func Programs() (string, error) {
	return run("readelf", "-l", "-W")
}

func Sections() (string, error) {
	return run("readelf", "-S", "-W")
}

func Symbols() (string, error) {
	return run("readelf", "-s", "-W")
}

func Dynamic() (string, error) {
	return run("readelf", "-d", "-W")
}

func Relocs() (string, error) {
	return run("readelf", "-r", "-W")
}

func Notes() (string, error) {
	return run("readelf", "-n", "-W")
}

func Security() (string, error) {
	return run("readelf", "-l", "-d", "-W")
}

func Assembly() (string, error) {
	return run("objdump", "-d", "-M", "intel")
}

func RawData() (string, error) {
	return run("objdump", "-s")
}

func Debug() (string, error) {
	return run("readelf", "--debug-dump=info", "-W")
}
