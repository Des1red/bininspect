package binary

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"math"
)

const (
	maxELFMetadataBytes   uint64          = 32 << 20
	maxELFMetadataRecords uint64          = 1 << 20
	elfSHTRELR            elf.SectionType = 19
)

type ELFSymbol struct {
	TableSection int
	Index        uint32

	Name  string
	Value uint64
	Size  uint64

	Binding    elf.SymBind
	Type       elf.SymType
	Visibility elf.SymVis

	SectionIndex uint32
}

type ELFRelocation struct {
	Section       int
	Index         int
	TargetSection int
	SymbolTable   int

	SymbolIndex uint32
	SymbolName  string

	Offset uint64
	Type   uint32

	Addend    int64
	HasAddend bool
	Encoding  string
}

type ELFMetadata struct {
	Symbols     []ELFSymbol
	Relocations []ELFRelocation
}

func ParseELFMetadata(
	reader io.ReaderAt,
	size uint64,
) (ELFMetadata, error) {
	var result ELFMetadata

	if reader == nil {
		return result, fmt.Errorf("nil ELF metadata reader")
	}

	if size > math.MaxInt64 {
		return result, fmt.Errorf(
			"ELF too large: %d", size,
		)
	}

	bounded := io.NewSectionReader(
		reader, 0, int64(size),
	)

	if err := preflightELF(bounded, size); err != nil {
		return result, err
	}

	f, err := elf.NewFile(bounded)
	if err != nil {
		return result, fmt.Errorf(
			"parsing ELF metadata: %w", err,
		)
	}

	if f.Type != elf.ET_REL &&
		f.Type != elf.ET_EXEC &&
		f.Type != elf.ET_DYN {
		return result, fmt.Errorf(
			"unsupported ELF type %s", f.Type,
		)
	}

	tables := make(map[int][]ELFSymbol)

	for i, s := range f.Sections {
		if s.Type != elf.SHT_SYMTAB &&
			s.Type != elf.SHT_DYNSYM {
			continue
		}

		if s.Link == 0 ||
			int(s.Link) >= len(f.Sections) ||
			f.Sections[s.Link].Type != elf.SHT_STRTAB {
			return result, fmt.Errorf(
				"symbols section %d: invalid string-table link %d",
				i, s.Link,
			)
		}

		entrySize := uint64(16)
		if f.Class == elf.ELFCLASS64 {
			entrySize = 24
		}

		data, err := elfSectionData(s)
		if err != nil {
			return result, fmt.Errorf(
				"reading symbols section %d: %w", i, err,
			)
		}

		if s.Entsize < entrySize ||
			s.Entsize == 0 ||
			uint64(len(data))%s.Entsize != 0 {
			return result, fmt.Errorf(
				"symbols section %d: invalid entry size/count",
				i,
			)
		}

		count := uint64(len(data)) / s.Entsize

		if count > maxELFMetadataRecords {
			return result, fmt.Errorf(
				"symbols section %d: excessive symbols", i,
			)
		}

		stringsData, err := elfSectionData(
			f.Sections[s.Link],
		)
		if err != nil {
			return result, fmt.Errorf(
				"symbols section %d: string table: %w",
				i, err,
			)
		}

		var ext []byte

		for j, x := range f.Sections {
			if x.Type != elf.SHT_SYMTAB_SHNDX ||
				int(x.Link) != i {
				continue
			}

			if ext != nil {
				return result, fmt.Errorf(
					"symbols section %d: duplicate SHNDX table",
					i,
				)
			}

			ext, err = elfSectionData(x)
			if err != nil {
				return result, fmt.Errorf(
					"SHNDX section %d: %w", j, err,
				)
			}

			if uint64(len(ext)) != count*4 {
				return result, fmt.Errorf(
					"SHNDX section %d: invalid entry count",
					j,
				)
			}
		}

		symbols := make([]ELFSymbol, 0, int(count))

		for index := uint64(0); index < count; index++ {
			entry := data[index*s.Entsize:]

			var nameOffset uint32
			var value, symbolSize uint64
			var info, other byte
			var shndx uint16

			bo := f.ByteOrder

			if f.Class == elf.ELFCLASS32 {
				nameOffset = bo.Uint32(entry[0:4])
				value = uint64(bo.Uint32(entry[4:8]))
				symbolSize = uint64(bo.Uint32(entry[8:12]))
				info = entry[12]
				other = entry[13]
				shndx = bo.Uint16(entry[14:16])
			} else {
				nameOffset = bo.Uint32(entry[0:4])
				info = entry[4]
				other = entry[5]
				shndx = bo.Uint16(entry[6:8])
				value = bo.Uint64(entry[8:16])
				symbolSize = bo.Uint64(entry[16:24])
			}

			name, err := elfSymbolName(
				stringsData, nameOffset,
			)
			if err != nil {
				return result, fmt.Errorf(
					"symbol section %d index %d: %w",
					i, index, err,
				)
			}

			sectionIndex := uint32(shndx)

			if shndx == uint16(elf.SHN_XINDEX) {
				if ext == nil {
					return result, fmt.Errorf(
						"symbol section %d index %d: missing SHNDX",
						i, index,
					)
				}

				sectionIndex = bo.Uint32(
					ext[index*4 : index*4+4],
				)
			}

			if shndx == uint16(elf.SHN_XINDEX) &&
				uint64(sectionIndex) >= uint64(len(f.Sections)) {
				return result, fmt.Errorf(
					"symbol section %d index %d: invalid extended section index %d",
					i, index, sectionIndex,
				)
			}

			if sectionIndex > 0 &&
				sectionIndex < uint32(elf.SHN_LORESERVE) &&
				int(sectionIndex) >= len(f.Sections) {
				return result, fmt.Errorf(
					"symbol section %d index %d: invalid section index %d",
					i, index, sectionIndex,
				)
			}

			symbol := ELFSymbol{
				TableSection: i,
				Index:        uint32(index),
				Name:         name,
				Value:        value,
				Size:         symbolSize,
				Binding:      elf.ST_BIND(info),
				Type:         elf.ST_TYPE(info),
				Visibility:   elf.ST_VISIBILITY(other),
				SectionIndex: sectionIndex,
			}

			symbols = append(symbols, symbol)
			result.Symbols = append(result.Symbols, symbol)
		}

		tables[i] = symbols
	}

	for i, s := range f.Sections {
		if s.Type != elf.SHT_REL &&
			s.Type != elf.SHT_RELA &&
			s.Type != elfSHTRELR &&
			s.Type != elfSHTAndroidREL &&
			s.Type != elfSHTAndroidRELA &&
			s.Type != elfSHTAndroidRELR {
			continue
		}

		data, err := elfSectionData(s)
		if err != nil {
			return result, fmt.Errorf(
				"relocations section %d: %w", i, err,
			)
		}

		switch s.Type {
		case elfSHTAndroidREL,
			elfSHTAndroidRELA,
			elfSHTAndroidRELR:

			if err := appendAndroidSectionRelocations(
				&result,
				f,
				i,
				s,
				data,
				tables,
			); err != nil {
				return ELFMetadata{}, err
			}

			continue
		}

		if s.Type == elfSHTRELR {
			if err := parseELFRELR(
				&result, i, s, data, f,
			); err != nil {
				return ELFMetadata{}, err
			}
			continue
		}

		symbols, ok := tables[int(s.Link)]
		if !ok {
			return result, fmt.Errorf(
				"relocations section %d: invalid symbol table link %d",
				i, s.Link,
			)
		}

		if f.Type == elf.ET_REL &&
			(s.Info == 0 || int(s.Info) >= len(f.Sections)) {
			return result, fmt.Errorf(
				"relocations section %d: invalid target section %d",
				i, s.Info,
			)
		}

		entrySize := uint64(8)
		if s.Type == elf.SHT_RELA {
			entrySize = 12
		}

		if f.Class == elf.ELFCLASS64 {
			entrySize = 16
			if s.Type == elf.SHT_RELA {
				entrySize = 24
			}
		}

		if s.Entsize < entrySize ||
			s.Entsize == 0 ||
			uint64(len(data))%s.Entsize != 0 {
			return result, fmt.Errorf(
				"relocations section %d: invalid entry size/count",
				i,
			)
		}

		count := uint64(len(data)) / s.Entsize

		if count > maxELFMetadataRecords {
			return result, fmt.Errorf(
				"relocations section %d: excessive records",
				i,
			)
		}

		for index := uint64(0); index < count; index++ {
			entry := data[index*s.Entsize:]

			var offset, info uint64
			var addend int64

			if f.Class == elf.ELFCLASS32 {
				offset = uint64(
					f.ByteOrder.Uint32(entry[0:4]),
				)
				info = uint64(
					f.ByteOrder.Uint32(entry[4:8]),
				)

				if s.Type == elf.SHT_RELA {
					addend = int64(int32(
						f.ByteOrder.Uint32(entry[8:12]),
					))
				}
			} else {
				offset = f.ByteOrder.Uint64(entry[0:8])
				info = f.ByteOrder.Uint64(entry[8:16])

				if s.Type == elf.SHT_RELA {
					addend = int64(
						f.ByteOrder.Uint64(entry[16:24]),
					)
				}
			}

			var symbolIndex, typ uint32

			if f.Class == elf.ELFCLASS32 {
				symbolIndex = uint32(info) >> 8
				typ = uint32(info) & 0xff
			} else {
				symbolIndex = uint32(info >> 32)
				typ = uint32(info)
			}

			if uint64(symbolIndex) >= uint64(len(symbols)) {
				return result, fmt.Errorf(
					"relocations section %d index %d: invalid symbol index %d",
					i, index, symbolIndex,
				)
			}

			if f.Type == elf.ET_REL &&
				offset >= f.Sections[s.Info].Size {
				return result, fmt.Errorf(
					"relocations section %d index %d: target offset out of bounds",
					i, index,
				)
			}

			encoding := "REL"
			if s.Type == elf.SHT_RELA {
				encoding = "RELA"
			}

			result.Relocations = append(
				result.Relocations,
				ELFRelocation{
					Section:       i,
					Index:         int(index),
					TargetSection: int(s.Info),
					SymbolTable:   int(s.Link),
					SymbolIndex:   symbolIndex,
					SymbolName:    symbols[symbolIndex].Name,
					Offset:        offset,
					Type:          typ,
					Addend:        addend,
					HasAddend:     s.Type == elf.SHT_RELA,
					Encoding:      encoding,
				},
			)
		}
	}

	return result, nil
}

func elfSectionData(s *elf.Section) ([]byte, error) {
	if s.Type == elf.SHT_NOBITS {
		return nil, fmt.Errorf(
			"section %q has no file data", s.Name,
		)
	}

	if s.Size > maxELFMetadataBytes {
		return nil, fmt.Errorf(
			"section %q exceeds %d-byte metadata limit",
			s.Name, maxELFMetadataBytes,
		)
	}

	data := make([]byte, int(s.Size))

	if _, err := io.ReadFull(s.Open(), data); err != nil {
		return nil, err
	}

	return data, nil
}

func elfSymbolName(
	table []byte,
	offset uint32,
) (string, error) {
	if uint64(offset) >= uint64(len(table)) {
		return "", fmt.Errorf(
			"invalid string offset %d", offset,
		)
	}

	tail := table[offset:]
	end := bytes.IndexByte(tail, 0)

	if end < 0 {
		return "", fmt.Errorf(
			"unterminated symbol name at %d", offset,
		)
	}

	return string(tail[:end]), nil
}

func parseELFRELR(
	result *ELFMetadata,
	sectionIndex int,
	s *elf.Section,
	data []byte,
	f *elf.File,
) error {
	width := uint64(4)
	if f.Class == elf.ELFCLASS64 {
		width = 8
	}

	if s.Entsize != 0 && s.Entsize != width {
		return fmt.Errorf(
			"RELR section %d: invalid entry size", sectionIndex,
		)
	}

	if uint64(len(data))%width != 0 {
		return fmt.Errorf(
			"RELR section %d: truncated entries", sectionIndex,
		)
	}

	var cursor uint64
	var haveBase bool
	var index int
	maxAddress := uint64(math.MaxUint64)

	if f.Class == elf.ELFCLASS32 {
		maxAddress = math.MaxUint32
	}
	add := func(addr uint64) error {
		if addr%width != 0 ||
			addr > maxAddress-(width-1) {
			return fmt.Errorf(
				"RELR section %d: invalid address %#x",
				sectionIndex, addr,
			)
		}
		if f.Type == elf.ET_REL &&
			(s.Info == 0 ||
				int(s.Info) >= len(f.Sections) ||
				addr >= f.Sections[s.Info].Size) {
			return fmt.Errorf(
				"RELR section %d: invalid target offset",
				sectionIndex,
			)
		}

		if uint64(index) >= maxELFMetadataRecords {
			return fmt.Errorf(
				"RELR section %d: excessive expanded relocations",
				sectionIndex,
			)
		}

		result.Relocations = append(
			result.Relocations,
			ELFRelocation{
				Section:       sectionIndex,
				Index:         index,
				TargetSection: int(s.Info),
				Offset:        addr,
				Encoding:      "RELR",
			},
		)

		index++
		return nil
	}

	for i := uint64(0); i < uint64(len(data)); i += width {
		var entry uint64

		if width == 4 {
			entry = uint64(
				f.ByteOrder.Uint32(data[i : i+4]),
			)
		} else {
			entry = f.ByteOrder.Uint64(data[i : i+8])
		}

		if entry&1 == 0 {
			if entry > math.MaxUint64-width {
				return fmt.Errorf(
					"RELR section %d: address overflow",
					sectionIndex,
				)
			}

			if err := add(entry); err != nil {
				return err
			}

			cursor = entry + width
			haveBase = true
		} else {
			if !haveBase {
				return fmt.Errorf(
					"RELR section %d: bitmap without base",
					sectionIndex,
				)
			}

			bits := width * 8

			for bit := uint64(1); bit < bits; bit++ {
				if entry&(uint64(1)<<bit) == 0 {
					continue
				}

				delta := (bit - 1) * width

				if cursor > math.MaxUint64-delta {
					return fmt.Errorf(
						"RELR section %d: address overflow",
						sectionIndex,
					)
				}

				if err := add(cursor + delta); err != nil {
					return err
				}
			}

			advance := (bits - 1) * width

			if cursor > math.MaxUint64-advance {
				return fmt.Errorf(
					"RELR section %d: address overflow",
					sectionIndex,
				)
			}

			cursor += advance
		}
	}

	return nil
}
