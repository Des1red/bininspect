package binary

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

var (
	ErrInvalidELFSection = errors.New(
		"invalid ELF section index",
	)
	ErrCompressedELFSection = errors.New(
		"compressed ELF section has no direct file offset",
	)
)

type ELFObjectSection struct {
	Index      int
	Name       string
	Type       elf.SectionType
	Flags      elf.SectionFlag
	Address    uint64
	Offset     uint64
	FileSize   uint64
	Size       uint64
	Alignment  uint64
	EntrySize  uint64
	Link       uint32
	Info       uint32
	Compressed bool
}

type ELFObject struct {
	Info        Info
	sections    []ELFObjectSection
	rawSections []*elf.Section
}

// ParseELFObject parses relocatable ELF objects, where section offsets,
// not final virtual addresses, identify code and data locations.
// The caller owns reader and must keep it open while the object is used.
func ParseELFObject(
	reader io.ReaderAt,
	fileSize uint64,
) (*ELFObject, error) {
	if reader == nil {
		return nil, errors.New("nil ELF reader")
	}

	if fileSize > math.MaxInt64 {
		return nil, fmt.Errorf(
			"ELF size exceeds supported reader offsets: %d",
			fileSize,
		)
	}

	bounded := io.NewSectionReader(
		reader,
		0,
		int64(fileSize),
	)

	if err := preflightELF(bounded, fileSize); err != nil {
		return nil, fmt.Errorf("ELF header: %w", err)
	}

	file, err := elf.NewFile(bounded)
	if err != nil {
		return nil, fmt.Errorf(
			"parsing ELF object: %w",
			err,
		)
	}

	if file.Type != elf.ET_REL {
		return nil, fmt.Errorf(
			"%w: %s (expected ET_REL)",
			ErrUnsupportedELFType,
			file.Type,
		)
	}

	info, err := elfImageInfo(file)
	if err != nil {
		return nil, err
	}

	if len(file.Sections) == 0 ||
		file.Sections[0].Type != elf.SHT_NULL {
		return nil, errors.New(
			"ELF object lacks the initial NULL section",
		)
	}

	object := &ELFObject{
		Info:        info,
		rawSections: file.Sections,
		sections: make(
			[]ELFObjectSection,
			0,
			len(file.Sections),
		),
	}

	for index, section := range file.Sections {
		// Legacy .zdebug sections store their uncompressed
		// size in the section payload.
		// Open allows debug/elf to determine that size.
		if strings.HasPrefix(section.Name, ".zdebug") {
			_ = section.Open()
		}

		meta := ELFObjectSection{
			Index:     index,
			Name:      section.Name,
			Type:      section.Type,
			Flags:     section.Flags,
			Address:   section.Addr,
			Offset:    section.Offset,
			FileSize:  section.FileSize,
			Size:      section.Size,
			Alignment: section.Addralign,
			EntrySize: section.Entsize,
			Link:      section.Link,
			Info:      section.Info,
			Compressed: section.Flags&elf.SHF_COMPRESSED != 0 ||
				(strings.HasPrefix(section.Name, ".zdebug") &&
					section.Size != section.FileSize),
		}

		if index > 0 {
			if meta.Alignment > 1 &&
				meta.Alignment&(meta.Alignment-1) != 0 {
				return nil, fmt.Errorf(
					"section[%d] %q: alignment is not a power of two",
					index,
					meta.Name,
				)
			}

			if meta.Size > math.MaxInt64 {
				return nil, fmt.Errorf(
					"section[%d] %q: logical size exceeds int64",
					index,
					meta.Name,
				)
			}

			// NOBITS sections occupy memory without
			// requiring corresponding file bytes.
			if meta.Type != elf.SHT_NOBITS {
				if meta.Offset > fileSize ||
					meta.FileSize > fileSize-meta.Offset {
					return nil, fmt.Errorf(
						"section[%d] %q: contents extend beyond file",
						index,
						meta.Name,
					)
				}
			}

			if meta.Flags&elf.SHF_COMPRESSED != 0 &&
				meta.Flags&elf.SHF_ALLOC != 0 {
				return nil, fmt.Errorf(
					"section[%d] %q: compressed allocatable section",
					index,
					meta.Name,
				)
			}
		}

		object.sections = append(object.sections, meta)
	}

	return object, nil
}

func (object *ELFObject) Sections() []ELFObjectSection {
	return append(
		[]ELFObjectSection(nil),
		object.sections...,
	)
}

func (object *ELFObject) section(
	index int,
) (ELFObjectSection, error) {
	if index <= 0 || index >= len(object.sections) {
		return ELFObjectSection{}, fmt.Errorf(
			"section index %d: %w",
			index,
			ErrInvalidELFSection,
		)
	}

	return object.sections[index], nil
}

// SectionFileOffset resolves a section-relative location to
// an exact offset in the binary file.
//
// NOBITS and compressed sections have no direct mapping.
func (object *ELFObject) SectionFileOffset(
	index int,
	offset uint64,
) (uint64, error) {
	section, err := object.section(index)
	if err != nil {
		return 0, err
	}

	if section.Compressed {
		return 0, fmt.Errorf(
			"section %q: %w",
			section.Name,
			ErrCompressedELFSection,
		)
	}

	if section.Type == elf.SHT_NOBITS {
		return 0, fmt.Errorf(
			"section %q: %w",
			section.Name,
			ErrNotFileBacked,
		)
	}

	if offset >= section.Size {
		return 0, fmt.Errorf(
			"section %q offset %d: %w",
			section.Name,
			offset,
			ErrRegionBoundary,
		)
	}

	return section.Offset + offset, nil
}

// ReadSection returns exactly size bytes at a section-relative
// offset.
//
// Compressed sections are transparently decompressed.
// NOBITS sections are represented by zero-filled memory.
func (object *ELFObject) ReadSection(
	index int,
	offset uint64,
	size uint64,
) ([]byte, error) {
	section, err := object.section(index)
	if err != nil {
		return nil, err
	}

	if size > MaxReadSize {
		return nil, fmt.Errorf(
			"requested %d bytes exceeds %d-byte read limit",
			size,
			MaxReadSize,
		)
	}

	if offset > section.Size ||
		size > section.Size-offset {
		return nil, fmt.Errorf(
			"section %q offset %d size %d: %w",
			section.Name,
			offset,
			size,
			ErrRegionBoundary,
		)
	}

	result := make([]byte, int(size))

	if size == 0 || section.Type == elf.SHT_NOBITS {
		return result, nil
	}

	reader := object.rawSections[index].Open()

	if _, err := reader.Seek(
		int64(offset),
		io.SeekStart,
	); err != nil {
		return nil, fmt.Errorf(
			"seeking section %q: %w",
			section.Name,
			err,
		)
	}

	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, fmt.Errorf(
			"reading section %q: %w",
			section.Name,
			err,
		)
	}

	return result, nil
}
