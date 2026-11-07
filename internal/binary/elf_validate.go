package binary

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
)

type ELFCrossValidation struct {
	Mode                 string
	ComparedSymbols      int
	ComparedRelocations  int
	ComparedVersionBytes int
	SymbolCountComplete  bool
	Warnings             []string
}

func CrossValidateELF(
	reader io.ReaderAt,
	size uint64,
) (ELFCrossValidation, error) {
	var report ELFCrossValidation

	if err := preflightELF(reader, size); err != nil {
		return report, err
	}

	file, err := elf.NewFile(
		io.NewSectionReader(reader, 0, int64(size)),
	)
	if err != nil {
		return report, err
	}

	if file.Type == elf.ET_REL {
		if _, err := ParseELFObject(reader, size); err != nil {
			return report, err
		}

		if _, err := ParseELFMetadata(reader, size); err != nil {
			return report, err
		}

		report.Mode = "section-only"
		report.Warnings = append(
			report.Warnings,
			"ET_REL has no linked virtual-address dynamic metadata to compare",
		)

		return report, nil
	}

	if file.Type != elf.ET_DYN && file.Type != elf.ET_EXEC {
		return report, fmt.Errorf(
			"unsupported ELF type %s", file.Type,
		)
	}

	image, err := ParseELF(reader, size)
	if err != nil {
		return report, err
	}

	dynamicInfo, err := ParseELFDynamic(reader, size)
	if err != nil {
		return report, err
	}

	sectionMetadata, err := ParseELFMetadata(reader, size)
	if err != nil {
		return report, err
	}

	dynamicMetadata, err := ParseELFDynamicMetadata(
		reader, size,
	)
	if err != nil {
		return report, err
	}

	versions, err := ParseELFVersions(reader, size)
	if err != nil {
		return report, err
	}

	report.SymbolCountComplete =
		dynamicMetadata.SymbolCountComplete

	report.Warnings = append(
		report.Warnings,
		dynamicMetadata.Warnings...,
	)
	report.Warnings = append(
		report.Warnings,
		versions.Warnings...,
	)

	if len(file.Sections) == 0 {
		report.Mode = "dynamic-only"
		report.Warnings = append(
			report.Warnings,
			"Section header table absent: independent section comparison unavailable",
		)

		return report, nil
	}

	if !dynamicInfo.Present {
		report.Mode = "section-only"
		return report, nil
	}

	report.Mode = "dual-source"

	// Compare section-backed and dynamic symbols.
	dynsymSection := -1

	for i, section := range file.Sections {
		if section.Type != elf.SHT_DYNSYM {
			continue
		}

		if dynsymSection != -1 {
			return report, fmt.Errorf(
				"multiple SHT_DYNSYM sections",
			)
		}

		dynsymSection = i
	}

	if dynsymSection >= 0 {
		var sectionSymbols []ELFSymbol

		for _, symbol := range sectionMetadata.Symbols {
			if symbol.TableSection == dynsymSection {
				sectionSymbols = append(
					sectionSymbols, symbol,
				)
			}
		}

		if len(dynamicMetadata.Symbols) > len(sectionSymbols) {
			return report, fmt.Errorf(
				"dynamic symbols (%d) exceed section symbols (%d)",
				len(dynamicMetadata.Symbols),
				len(sectionSymbols),
			)
		}

		if dynamicMetadata.SymbolCountComplete &&
			len(dynamicMetadata.Symbols) != len(sectionSymbols) {
			return report, fmt.Errorf(
				"dynamic/section symbol counts disagree: %d != %d",
				len(dynamicMetadata.Symbols),
				len(sectionSymbols),
			)
		}

		for i, dynamicSymbol := range dynamicMetadata.Symbols {
			sectionSymbol := sectionSymbols[i]

			if dynamicSymbol.Index != sectionSymbol.Index ||
				dynamicSymbol.Name != sectionSymbol.Name ||
				dynamicSymbol.Value != sectionSymbol.Value ||
				dynamicSymbol.Size != sectionSymbol.Size ||
				dynamicSymbol.Binding != sectionSymbol.Binding ||
				dynamicSymbol.Type != sectionSymbol.Type ||
				dynamicSymbol.Visibility != sectionSymbol.Visibility ||
				dynamicSymbol.SectionIndex != sectionSymbol.SectionIndex {

				return report, fmt.Errorf(
					"dynamic symbol %d differs between DT_SYMTAB and SHT_DYNSYM (%q vs %q)",
					i,
					dynamicSymbol.Name,
					sectionSymbol.Name,
				)
			}

			report.ComparedSymbols++
		}

		if !dynamicMetadata.SymbolCountComplete &&
			len(dynamicMetadata.Symbols) < len(sectionSymbols) {
			report.Warnings = append(
				report.Warnings,
				"GNU hash supplied only a dynamic-symbol prefix; section table contains additional entries",
			)
		}

	} else if len(dynamicMetadata.Symbols) > 0 {
		report.Warnings = append(
			report.Warnings,
			"SHT_DYNSYM absent: dynamic symbols have no section-backed counterpart",
		)
	}

	// Compare all allocatable relocation sections against
	// the dynamic relocation records.
	var sectionRelocations []ELFRelocation
	hasRelocationSections := false

	for sectionIndex, section := range file.Sections {
		if section.Type != elf.SHT_REL &&
			section.Type != elf.SHT_RELA &&
			section.Type != elfSHTRELR &&
			section.Type != elfSHTAndroidREL &&
			section.Type != elfSHTAndroidRELA &&
			section.Type != elfSHTAndroidRELR {
			continue
		}

		if section.Flags&elf.SHF_ALLOC == 0 {
			continue
		}

		hasRelocationSections = true

		for _, relocation := range sectionMetadata.Relocations {
			if relocation.Section == sectionIndex {
				sectionRelocations = append(
					sectionRelocations,
					relocation,
				)
			}
		}
	}

	if hasRelocationSections {
		records := make(map[string]int)

		for _, relocation := range sectionRelocations {
			records[relocationSignature(relocation)]++
		}

		for _, relocation := range dynamicMetadata.Relocations {
			key := relocationSignature(relocation)

			if records[key] == 0 {
				return report, fmt.Errorf(
					"dynamic relocation at %#x not found in section-backed relocations",
					relocation.Offset,
				)
			}

			records[key]--
			report.ComparedRelocations++
		}

		for key, count := range records {
			if count != 0 {
				return report, fmt.Errorf(
					"%d unpaired section relocation(s): %s",
					count, key,
				)
			}
		}

	} else if len(dynamicMetadata.Relocations) > 0 {
		report.Warnings = append(
			report.Warnings,
			"No allocatable relocation sections available for independent comparison",
		)
	}

	// Compare the version-table virtual addresses and bytes
	// against their section-header representations.
	checks := []struct {
		tag elf.DynTag
		typ elf.SectionType
	}{
		{elf.DT_VERSYM, elf.SHT_GNU_VERSYM},
		{elf.DT_VERDEF, elf.SHT_GNU_VERDEF},
		{elf.DT_VERNEED, elf.SHT_GNU_VERNEED},
	}

	for _, check := range checks {
		address, hasTag, err := uniqueDynamicTag(
			dynamicInfo.Entries,
			check.tag,
		)
		if err != nil {
			return report, err
		}

		var section *elf.Section

		for _, candidate := range file.Sections {
			if candidate.Type != check.typ {
				continue
			}

			if section != nil {
				return report, fmt.Errorf(
					"multiple %s sections", check.typ,
				)
			}

			section = candidate
		}

		if !hasTag && section == nil {
			continue
		}

		if !hasTag || section == nil {
			report.Warnings = append(
				report.Warnings,
				fmt.Sprintf(
					"%s has no matching section/dynamic source",
					check.tag,
				),
			)
			continue
		}

		if section.Addr != address {
			return report, fmt.Errorf(
				"%s section address %#x differs from dynamic address %#x",
				check.tag,
				section.Addr,
				address,
			)
		}

		if section.Size > maxELFMetadataBytes {
			return report, fmt.Errorf(
				"%s version section exceeds limit",
				check.typ,
			)
		}

		sectionBytes, err := section.Data()
		if err != nil {
			return report, err
		}

		if uint64(len(sectionBytes)) != section.Size {
			return report, fmt.Errorf(
				"%s section size mismatch",
				check.typ,
			)
		}

		dynamicBytes, err := dynamicRead(
			image,
			address,
			section.Size,
		)
		if err != nil {
			return report, err
		}

		if !bytes.Equal(sectionBytes, dynamicBytes) {
			return report, fmt.Errorf(
				"%s section content differs from virtual data",
				check.tag,
			)
		}

		report.ComparedVersionBytes += len(sectionBytes)
	}

	if versions.Present && len(versions.Symbols) == 0 {
		report.Warnings = append(
			report.Warnings,
			"Version entries were found but no per-symbol versions were resolved",
		)
	}

	return report, nil
}

func relocationSignature(r ELFRelocation) string {
	kind := "REL"

	if r.Encoding == "RELR" {
		kind = "RELR"
	} else if r.HasAddend {
		kind = "RELA"
	}

	if kind == "RELR" {
		return fmt.Sprintf(
			"%s:%016x", kind, r.Offset,
		)
	}

	if r.HasAddend {
		return fmt.Sprintf(
			"%s:%016x:%08x:%08x:%016x",
			kind,
			r.Offset,
			r.Type,
			r.SymbolIndex,
			uint64(r.Addend),
		)
	}

	return fmt.Sprintf(
		"%s:%016x:%08x:%08x",
		kind,
		r.Offset,
		r.Type,
		r.SymbolIndex,
	)
}
