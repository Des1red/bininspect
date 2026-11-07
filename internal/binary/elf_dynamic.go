package binary

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
)

type ELFDynamicEntry struct {
	Tag   elf.DynTag
	Value uint64
}

type ELFDynamicInfo struct {
	Present bool
	Entries []ELFDynamicEntry
	Needed  []string
	SONAME  string
	RPATH   string
	RUNPATH string
}

// ParseELFDynamic reads PT_DYNAMIC directly, including ELF files
// without section headers. The caller retains ownership of reader.
func ParseELFDynamic(
	reader io.ReaderAt,
	fileSize uint64,
) (ELFDynamicInfo, error) {
	var result ELFDynamicInfo

	// Validate the ELF image and its memory mappings first.
	image, err := ParseELF(reader, fileSize)
	if err != nil {
		return result, err
	}

	if fileSize > math.MaxInt64 {
		return result, fmt.Errorf("ELF size exceeds reader limit")
	}

	file, err := elf.NewFile(
		io.NewSectionReader(reader, 0, int64(fileSize)),
	)
	if err != nil {
		return result, fmt.Errorf(
			"parsing ELF dynamic headers: %w", err,
		)
	}

	var dynamic *elf.Prog

	for _, program := range file.Progs {
		if program.Type != elf.PT_DYNAMIC {
			continue
		}

		if dynamic != nil {
			return result, errors.New(
				"multiple PT_DYNAMIC segments",
			)
		}

		dynamic = program
	}

	if dynamic == nil {
		return result, nil
	}

	result.Present = true

	width := uint64(8)
	if image.Info.Bits == 64 {
		width = 16
	}

	if dynamic.Filesz == 0 || dynamic.Filesz%width != 0 {
		return result, fmt.Errorf(
			"PT_DYNAMIC has invalid file size %d",
			dynamic.Filesz,
		)
	}

	if dynamic.Filesz > MaxReadSize ||
		dynamic.Filesz > dynamic.Memsz {
		return result, fmt.Errorf(
			"PT_DYNAMIC size exceeds supported bounds",
		)
	}

	offset, err := image.VirtualToFile(dynamic.Vaddr)
	if err != nil {
		return result, fmt.Errorf(
			"PT_DYNAMIC mapping: %w", err,
		)
	}

	if offset != dynamic.Off {
		return result, fmt.Errorf(
			"PT_DYNAMIC file offset %#x disagrees with mapped offset %#x",
			dynamic.Off,
			offset,
		)
	}

	data, err := image.ReadVirtual(
		dynamic.Vaddr,
		dynamic.Filesz,
	)
	if err != nil {
		return result, fmt.Errorf(
			"reading PT_DYNAMIC: %w", err,
		)
	}

	terminated := false

	for pos := uint64(0); pos < uint64(len(data)); pos += width {
		var tag, value uint64

		if width == 8 {
			tag = uint64(
				file.ByteOrder.Uint32(data[pos : pos+4]),
			)
			value = uint64(
				file.ByteOrder.Uint32(data[pos+4 : pos+8]),
			)
		} else {
			tag = file.ByteOrder.Uint64(
				data[pos : pos+8],
			)
			value = file.ByteOrder.Uint64(
				data[pos+8 : pos+16],
			)
		}

		if tag == uint64(elf.DT_NULL) {
			terminated = true
			break
		}

		result.Entries = append(
			result.Entries,
			ELFDynamicEntry{
				Tag:   elf.DynTag(tag),
				Value: value,
			},
		)
	}

	if !terminated {
		return result, errors.New(
			"PT_DYNAMIC has no DT_NULL terminator",
		)
	}

	// Determine whether dynamic string references exist.
	needStrings := false

	for _, entry := range result.Entries {
		switch entry.Tag {
		case elf.DT_NEEDED,
			elf.DT_SONAME,
			elf.DT_RPATH,
			elf.DT_RUNPATH:

			needStrings = true
		}
	}

	if !needStrings {
		return result, nil
	}

	strAddr, hasAddr, err := uniqueDynamicTag(
		result.Entries,
		elf.DT_STRTAB,
	)
	if err != nil {
		return result, err
	}

	strSize, hasSize, err := uniqueDynamicTag(
		result.Entries,
		elf.DT_STRSZ,
	)
	if err != nil {
		return result, err
	}

	if !hasAddr || !hasSize {
		return result, errors.New(
			"dynamic string references require DT_STRTAB and DT_STRSZ",
		)
	}

	if strSize == 0 || strSize > MaxReadSize {
		return result, fmt.Errorf(
			"invalid DT_STRSZ %d", strSize,
		)
	}

	stringsData, err := image.ReadVirtual(
		strAddr,
		strSize,
	)
	if err != nil {
		return result, fmt.Errorf(
			"reading DT_STRTAB: %w", err,
		)
	}

	for _, entry := range result.Entries {
		switch entry.Tag {
		case elf.DT_NEEDED,
			elf.DT_SONAME,
			elf.DT_RPATH,
			elf.DT_RUNPATH:

			name, err := elfDynamicString(
				stringsData,
				entry.Value,
			)
			if err != nil {
				return result, fmt.Errorf(
					"%s: %w", entry.Tag, err,
				)
			}

			switch entry.Tag {
			case elf.DT_NEEDED:
				result.Needed = append(
					result.Needed, name,
				)

			case elf.DT_SONAME:
				result.SONAME = name

			case elf.DT_RPATH:
				result.RPATH = name

			case elf.DT_RUNPATH:
				result.RUNPATH = name
			}
		}
	}

	return result, nil
}

func uniqueDynamicTag(
	entries []ELFDynamicEntry,
	tag elf.DynTag,
) (uint64, bool, error) {
	var value uint64
	var found bool

	for _, entry := range entries {
		if entry.Tag != tag {
			continue
		}

		if found && value != entry.Value {
			return 0, false, fmt.Errorf(
				"conflicting %s entries", tag,
			)
		}

		value = entry.Value
		found = true
	}

	return value, found, nil
}

func elfDynamicString(
	table []byte,
	offset uint64,
) (string, error) {
	if offset >= uint64(len(table)) {
		return "", fmt.Errorf(
			"string offset %d outside DT_STRTAB",
			offset,
		)
	}

	for i := int(offset); i < len(table); i++ {
		if table[i] == 0 {
			return string(
				table[int(offset):i],
			), nil
		}
	}

	return "", fmt.Errorf(
		"unterminated dynamic string at offset %d",
		offset,
	)
}
