package binary

import (
	"debug/elf"
	"fmt"
)

func appendAndroidSectionRelocations(
	result *ELFMetadata,
	file *elf.File,
	sectionIndex int,
	section *elf.Section,
	data []byte,
	symbols map[int][]ELFSymbol,
) error {
	bits := uint8(32)

	if file.Class == elf.ELFCLASS64 {
		bits = 64
	}

	var records []ELFRelocation
	var err error

	switch section.Type {
	case elfSHTAndroidREL, elfSHTAndroidRELA:
		records, err = decodeAndroidAPS2(
			data,
			bits,
			section.Type == elfSHTAndroidRELA,
		)

	case elfSHTAndroidRELR:
		word := uint64(bits / 8)

		if section.Entsize != 0 && section.Entsize != word {
			return fmt.Errorf(
				"section %d: invalid Android RELR entry size",
				sectionIndex,
			)
		}

		records, err = decodeAndroidRELR(
			data,
			bits,
			file.ByteOrder,
		)

	default:
		return fmt.Errorf(
			"section %d: unsupported Android relocation type",
			sectionIndex,
		)
	}

	if err != nil {
		return fmt.Errorf("section %d: %w", sectionIndex, err)
	}

	if file.Type == elf.ET_REL &&
		(section.Info == 0 ||
			int(section.Info) >= len(file.Sections)) {
		return fmt.Errorf(
			"section %d: invalid target section",
			sectionIndex,
		)
	}

	table, hasSymbols := symbols[int(section.Link)]

	if section.Type != elfSHTAndroidRELR &&
		section.Link != 0 && !hasSymbols {
		return fmt.Errorf(
			"section %d: invalid symbol table link",
			sectionIndex,
		)
	}

	for index, record := range records {
		if file.Type == elf.ET_REL &&
			record.Offset >= file.Sections[section.Info].Size {
			return fmt.Errorf(
				"section %d: relocation offset outside target section",
				sectionIndex,
			)
		}

		if section.Type != elfSHTAndroidRELR {
			if hasSymbols {
				if uint64(record.SymbolIndex) >=
					uint64(len(table)) {
					return fmt.Errorf(
						"section %d: invalid symbol index %d",
						sectionIndex,
						record.SymbolIndex,
					)
				}

				record.SymbolName = table[record.SymbolIndex].Name
			} else if record.SymbolIndex != 0 {
				return fmt.Errorf(
					"section %d: missing symbol table",
					sectionIndex,
				)
			}
		}

		record.Section = sectionIndex
		record.Index = index
		record.TargetSection = int(section.Info)

		if section.Type != elfSHTAndroidRELR {
			record.SymbolTable = int(section.Link)
		}

		result.Relocations = append(
			result.Relocations,
			record,
		)
	}

	return nil
}
