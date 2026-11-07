package binary

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

type ELFVersionSymbol struct {
	SymbolIndex uint32
	SymbolName  string
	Raw         uint16
	Index       uint16
	Hidden      bool
	Name        string
	Library     string
	Kind        string
}

type ELFVersionDefinition struct {
	Index uint16
	Flags uint16
	Hash  uint32
	Names []string
}

type ELFVersionRequirement struct {
	Library string
	Index   uint16
	Name    string
	Flags   uint16
	Hash    uint32
}

type ELFVersions struct {
	Present             bool
	Symbols             []ELFVersionSymbol
	Definitions         []ELFVersionDefinition
	Requirements        []ELFVersionRequirement
	SymbolCountComplete bool
	Warnings            []string
}

// ParseELFVersions reads GNU symbol versioning from PT_DYNAMIC.
// Section headers are used when available to recover the complete
// dynamic symbol count. Sectionless files remain supported.
func ParseELFVersions(
	reader io.ReaderAt,
	size uint64,
) (ELFVersions, error) {
	var result ELFVersions

	image, err := ParseELF(reader, size)
	if err != nil {
		return result, err
	}

	dynamic, err := ParseELFDynamic(reader, size)
	if err != nil {
		return result, err
	}

	if !dynamic.Present {
		return result, nil
	}

	meta, err := ParseELFDynamicMetadata(reader, size)
	if err != nil {
		return result, err
	}

	result.SymbolCountComplete = meta.SymbolCountComplete
	result.Warnings = append(result.Warnings, meta.Warnings...)

	file, err := elf.NewFile(
		io.NewSectionReader(reader, 0, int64(size)),
	)
	if err != nil {
		return result, err
	}

	symbols := meta.Symbols

	// Section-backed dynsym can establish the complete symbol count
	// even when GNU hash provides only a lower bound.
	for index, section := range file.Sections {
		if section.Type != elf.SHT_DYNSYM {
			continue
		}

		if section.Entsize == 0 ||
			section.Size%section.Entsize != 0 {
			return result, fmt.Errorf(
				"dynsym section %d has invalid entries",
				index,
			)
		}

		metadata, err := ParseELFMetadata(reader, size)
		if err != nil {
			return result, err
		}

		var sectionSymbols []ELFSymbol

		for _, symbol := range metadata.Symbols {
			if symbol.TableSection == index {
				sectionSymbols = append(
					sectionSymbols, symbol,
				)
			}
		}

		if len(sectionSymbols) !=
			int(section.Size/section.Entsize) {
			return result, fmt.Errorf(
				"dynsym section %d symbol count mismatch",
				index,
			)
		}

		if len(meta.Symbols) > len(sectionSymbols) {
			return result, errors.New(
				"dynamic symbols exceed section symbol count",
			)
		}

		symbols = sectionSymbols
		result.SymbolCountComplete = true
		break
	}

	versymAddr, hasVersym, err := uniqueDynamicTag(
		dynamic.Entries, elf.DT_VERSYM,
	)
	if err != nil {
		return result, err
	}

	needAddr, hasNeed, err := uniqueDynamicTag(
		dynamic.Entries, elf.DT_VERNEED,
	)
	if err != nil {
		return result, err
	}

	needCount, hasNeedCount, err := uniqueDynamicTag(
		dynamic.Entries, elf.DT_VERNEEDNUM,
	)
	if err != nil {
		return result, err
	}

	defAddr, hasDef, err := uniqueDynamicTag(
		dynamic.Entries, elf.DT_VERDEF,
	)
	if err != nil {
		return result, err
	}

	defCount, hasDefCount, err := uniqueDynamicTag(
		dynamic.Entries, elf.DT_VERDEFNUM,
	)
	if err != nil {
		return result, err
	}

	if hasNeed != hasNeedCount ||
		hasDef != hasDefCount {
		return result, errors.New(
			"version definition/requirement pointer and count must occur together",
		)
	}

	result.Present = hasVersym || hasNeed || hasDef

	if !result.Present {
		return result, nil
	}

	var strtab []byte

	if hasNeed || hasDef {
		address, hasAddress, err := uniqueDynamicTag(
			dynamic.Entries, elf.DT_STRTAB,
		)
		if err != nil {
			return result, err
		}

		length, hasLength, err := uniqueDynamicTag(
			dynamic.Entries, elf.DT_STRSZ,
		)
		if err != nil {
			return result, err
		}

		if !hasAddress || !hasLength ||
			length == 0 ||
			length > maxELFMetadataBytes {
			return result, errors.New(
				"GNU version entries require bounded DT_STRTAB/DT_STRSZ",
			)
		}

		strtab, err = dynamicRead(
			image, address, length,
		)
		if err != nil {
			return result, fmt.Errorf(
				"version string table: %w", err,
			)
		}
	}

	if hasNeed {
		result.Requirements, err = readELFVersionNeeds(
			image,
			needAddr,
			needCount,
			strtab,
			file.ByteOrder,
		)
		if err != nil {
			return result, err
		}
	}

	if hasDef {
		result.Definitions, err = readELFVersionDefinitions(
			image,
			defAddr,
			defCount,
			strtab,
			file.ByteOrder,
		)
		if err != nil {
			return result, err
		}
	}

	definitions := make(
		map[uint16]ELFVersionDefinition,
	)

	for _, definition := range result.Definitions {
		if _, exists := definitions[definition.Index]; exists {
			return result, fmt.Errorf(
				"duplicate version definition %d",
				definition.Index,
			)
		}

		definitions[definition.Index] = definition
	}

	requirements := make(
		map[uint16]ELFVersionRequirement,
	)

	for _, requirement := range result.Requirements {
		if _, exists := requirements[requirement.Index]; exists {
			return result, fmt.Errorf(
				"duplicate version requirement %d",
				requirement.Index,
			)
		}

		if _, exists := definitions[requirement.Index]; exists {
			return result, fmt.Errorf(
				"version index %d is both required and defined",
				requirement.Index,
			)
		}

		requirements[requirement.Index] = requirement
	}

	if !hasVersym {
		result.Warnings = append(
			result.Warnings,
			"Version definitions/requirements exist without DT_VERSYM; per-symbol assignment unavailable",
		)
		return result, nil
	}

	if len(symbols) == 0 {
		result.Warnings = append(
			result.Warnings,
			"DT_VERSYM exists but dynamic symbol count cannot be established",
		)
		return result, nil
	}

	if uint64(len(symbols)) > maxELFMetadataBytes/2 {
		return result, errors.New(
			"too many version symbols",
		)
	}

	data, err := dynamicRead(
		image,
		versymAddr,
		uint64(len(symbols))*2,
	)
	if err != nil {
		return result, fmt.Errorf(
			"DT_VERSYM: %w", err,
		)
	}

	for index, symbol := range symbols {
		raw := file.ByteOrder.Uint16(
			data[index*2 : index*2+2],
		)

		versionIndex := raw & 0x7fff

		version := ELFVersionSymbol{
			SymbolIndex: uint32(index),
			SymbolName:  symbol.Name,
			Raw:         raw,
			Index:       versionIndex,
			Hidden:      raw&0x8000 != 0,
		}

		switch versionIndex {
		case 0:
			version.Kind = "local"

		case 1:
			version.Kind = "global"

		default:
			if requirement, ok := requirements[versionIndex]; ok {
				version.Kind = "required"
				version.Name = requirement.Name
				version.Library = requirement.Library

			} else if definition, ok := definitions[versionIndex]; ok {
				version.Kind = "defined"
				version.Name = definition.Names[0]

			} else {
				return result, fmt.Errorf(
					"dynsym index %d (%s): unresolved GNU version index %d",
					index,
					symbol.Name,
					versionIndex,
				)
			}
		}

		result.Symbols = append(
			result.Symbols, version,
		)
	}

	if !result.SymbolCountComplete {
		result.Warnings = append(
			result.Warnings,
			"Version symbols cover only the recoverable dynamic-symbol prefix",
		)
	}

	return result, nil
}

func versionBytes(
	image *Image,
	base, relative, count uint64,
) ([]byte, error) {
	if base > math.MaxUint64-relative {
		return nil, errors.New(
			"version offset overflows virtual address",
		)
	}

	return dynamicRead(
		image, base+relative, count,
	)
}

func checkedAdvance(
	base, cursor, step uint64,
) (uint64, error) {
	if step == 0 ||
		cursor > math.MaxUint64-step ||
		base > math.MaxUint64-(cursor+step) {
		return 0, errors.New(
			"invalid version linked-list offset",
		)
	}

	return cursor + step, nil
}

func readELFVersionNeeds(
	image *Image,
	address, count uint64,
	strtab []byte,
	order binary.ByteOrder,
) ([]ELFVersionRequirement, error) {
	if count == 0 || count > maxELFMetadataRecords {
		return nil, fmt.Errorf(
			"invalid DT_VERNEEDNUM %d", count,
		)
	}

	var requirements []ELFVersionRequirement
	var cursor uint64

	for i := uint64(0); i < count; i++ {
		header, err := versionBytes(
			image, address, cursor, 16,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"verneed[%d]: %w", i, err,
			)
		}

		if order.Uint16(header[0:2]) != 1 {
			return nil, fmt.Errorf(
				"verneed[%d]: unsupported version", i,
			)
		}

		auxCount := uint64(
			order.Uint16(header[2:4]),
		)

		if auxCount == 0 ||
			auxCount > maxELFMetadataRecords {
			return nil, fmt.Errorf(
				"verneed[%d]: invalid auxiliary count", i,
			)
		}

		library, err := elfDynamicString(
			strtab,
			uint64(order.Uint32(header[4:8])),
		)
		if err != nil {
			return nil, fmt.Errorf(
				"verneed[%d] library: %w", i, err,
			)
		}
		if library == "" {
			return nil, fmt.Errorf(
				"verneed[%d]: empty library name", i,
			)
		}

		auxOffset := uint64(order.Uint32(header[8:12]))
		next := uint64(order.Uint32(header[12:16]))

		if auxOffset < 16 {
			return nil, fmt.Errorf(
				"verneed[%d]: invalid auxiliary offset", i,
			)
		}
		if next > 0 && next < 16 {
			return nil, fmt.Errorf(
				"verneed[%d]: invalid next offset", i,
			)
		}

		aux, err := checkedAdvance(
			0, cursor, auxOffset,
		)
		if err != nil {
			return nil, err
		}

		for j := uint64(0); j < auxCount; j++ {
			entry, err := versionBytes(
				image, address, aux, 16,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"verneed[%d] aux[%d]: %w",
					i, j, err,
				)
			}

			index := order.Uint16(entry[6:8]) & 0x7fff
			if index < 2 {
				return nil, fmt.Errorf(
					"verneed[%d] aux[%d]: invalid index %d",
					i, j, index,
				)
			}

			name, err := elfDynamicString(
				strtab,
				uint64(order.Uint32(entry[8:12])),
			)
			if err != nil {
				return nil, fmt.Errorf(
					"verneed[%d] aux[%d]: %w",
					i, j, err,
				)
			}
			if name == "" {
				return nil, fmt.Errorf(
					"verneed[%d] aux[%d]: empty name",
					i, j,
				)
			}

			requirements = append(
				requirements,
				ELFVersionRequirement{
					Library: library,
					Index:   index,
					Name:    name,
					Flags:   order.Uint16(entry[4:6]),
					Hash:    order.Uint32(entry[0:4]),
				},
			)

			if uint64(len(requirements)) > maxELFMetadataRecords {
				return nil, errors.New(
					"too many version requirements",
				)
			}

			step := uint64(order.Uint32(entry[12:16]))

			if j+1 < auxCount {
				if step < 16 {
					return nil, fmt.Errorf(
						"verneed[%d] aux[%d]: invalid next offset",
						i, j,
					)
				}

				aux, err = checkedAdvance(
					address, aux, step,
				)
				if err != nil {
					return nil, err
				}
			} else if step != 0 {
				return nil, fmt.Errorf(
					"verneed[%d]: final auxiliary has nonzero next offset",
					i,
				)
			}
		}

		if i+1 < count {
			if next == 0 {
				return nil, fmt.Errorf(
					"verneed[%d]: missing next node", i,
				)
			}

			cursor, err = checkedAdvance(
				address, cursor, next,
			)
			if err != nil {
				return nil, err
			}
		} else if next != 0 {
			return nil, fmt.Errorf(
				"verneed[%d]: unexpected trailing node", i,
			)
		}
	}

	return requirements, nil
}

func readELFVersionDefinitions(
	image *Image,
	address, count uint64,
	strtab []byte,
	order binary.ByteOrder,
) ([]ELFVersionDefinition, error) {
	if count == 0 || count > maxELFMetadataRecords {
		return nil, fmt.Errorf(
			"invalid DT_VERDEFNUM %d", count,
		)
	}

	var definitions []ELFVersionDefinition
	var cursor uint64

	for i := uint64(0); i < count; i++ {
		header, err := versionBytes(
			image, address, cursor, 20,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"verdef[%d]: %w", i, err,
			)
		}

		if order.Uint16(header[0:2]) != 1 {
			return nil, fmt.Errorf(
				"verdef[%d]: unsupported version", i,
			)
		}

		index := order.Uint16(header[4:6]) & 0x7fff
		if index == 0 {
			return nil, fmt.Errorf(
				"verdef[%d]: invalid version index zero", i,
			)
		}

		auxCount := uint64(
			order.Uint16(header[6:8]),
		)
		if auxCount == 0 ||
			auxCount > maxELFMetadataRecords {
			return nil, fmt.Errorf(
				"verdef[%d]: invalid auxiliary count", i,
			)
		}

		auxOffset := uint64(order.Uint32(header[12:16]))
		next := uint64(order.Uint32(header[16:20]))

		if auxOffset < 20 {
			return nil, fmt.Errorf(
				"verdef[%d]: invalid auxiliary offset", i,
			)
		}
		if next > 0 && next < 20 {
			return nil, fmt.Errorf(
				"verdef[%d]: invalid next offset", i,
			)
		}

		aux, err := checkedAdvance(
			0, cursor, auxOffset,
		)
		if err != nil {
			return nil, err
		}

		definition := ELFVersionDefinition{
			Index: index,
			Flags: order.Uint16(header[2:4]),
			Hash:  order.Uint32(header[8:12]),
		}

		for j := uint64(0); j < auxCount; j++ {
			entry, err := versionBytes(
				image, address, aux, 8,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"verdef[%d] aux[%d]: %w",
					i, j, err,
				)
			}

			name, err := elfDynamicString(
				strtab,
				uint64(order.Uint32(entry[0:4])),
			)
			if err != nil {
				return nil, fmt.Errorf(
					"verdef[%d] aux[%d]: %w",
					i, j, err,
				)
			}
			if name == "" {
				return nil, fmt.Errorf(
					"verdef[%d] aux[%d]: empty name",
					i, j,
				)
			}

			definition.Names = append(
				definition.Names, name,
			)

			step := uint64(order.Uint32(entry[4:8]))

			if j+1 < auxCount {
				if step < 8 {
					return nil, fmt.Errorf(
						"verdef[%d] aux[%d]: invalid next offset",
						i, j,
					)
				}

				aux, err = checkedAdvance(
					address, aux, step,
				)
				if err != nil {
					return nil, err
				}
			} else if step != 0 {
				return nil, fmt.Errorf(
					"verdef[%d]: final auxiliary has nonzero next offset",
					i,
				)
			}
		}

		definitions = append(
			definitions, definition,
		)

		if i+1 < count {
			if next == 0 {
				return nil, fmt.Errorf(
					"verdef[%d]: missing next node", i,
				)
			}

			cursor, err = checkedAdvance(
				address, cursor, next,
			)
			if err != nil {
				return nil, err
			}
		} else if next != 0 {
			return nil, fmt.Errorf(
				"verdef[%d]: unexpected trailing node", i,
			)
		}
	}

	return definitions, nil
}
