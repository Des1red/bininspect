package binary

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
)

// ELFResult keeps the structured ELF data needed by
// the decoder and analyzer.
//
// Image is set for ET_EXEC/ET_DYN.
// Object is set for ET_REL.
//
// The caller must keep reader open while using Image or Object.
type ELFResult struct {
	Info     Info
	Header   elf.FileHeader
	Programs []elf.ProgHeader
	Sections []elf.SectionHeader

	Image  *Image
	Object *ELFObject

	Metadata        ELFMetadata
	Dynamic         ELFDynamicInfo
	DynamicMetadata ELFDynamicMetadata
	Versions        ELFVersions
	Validation      ELFCrossValidation
}

func Engine(
	reader io.ReaderAt,
	size uint64,
) (*ELFResult, error) {
	file, err := openELFHeaders(reader, size)
	if err != nil {
		return nil, err
	}

	result := &ELFResult{
		Header: file.FileHeader,
	}

	for _, program := range file.Progs {
		result.Programs = append(
			result.Programs,
			program.ProgHeader,
		)
	}

	for _, section := range file.Sections {
		result.Sections = append(
			result.Sections,
			section.SectionHeader,
		)
	}

	switch file.Type {
	case elf.ET_REL:
		result.Object, err = ParseELFObject(
			reader, size,
		)
		if err == nil {
			result.Info = result.Object.Info
		}

	case elf.ET_EXEC, elf.ET_DYN:
		result.Image, err = ParseELF(
			reader, size,
		)
		if err == nil {
			result.Info = result.Image.Info
		}

	default:
		return nil, fmt.Errorf(
			"%w: %s",
			ErrUnsupportedELFType,
			file.Type,
		)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"ELF image/object: %w", err,
		)
	}

	result.Metadata, err = ParseELFMetadata(
		reader, size,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"ELF metadata: %w", err,
		)
	}

	if result.Image != nil {
		result.Dynamic, err = ParseELFDynamic(
			reader, size,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"ELF dynamic: %w", err,
			)
		}

		result.DynamicMetadata, err = ParseELFDynamicMetadata(
			reader, size,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"ELF dynamic metadata: %w", err,
			)
		}

		result.Versions, err = ParseELFVersions(
			reader, size,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"ELF versions: %w", err,
			)
		}
	}

	result.Validation, err = CrossValidateELF(
		reader, size,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"ELF cross-validation: %w", err,
		)
	}

	return result, nil
}

func openELFHeaders(
	reader io.ReaderAt,
	size uint64,
) (*elf.File, error) {
	if reader == nil {
		return nil, errors.New("nil ELF reader")
	}

	if size > math.MaxInt64 {
		return nil, fmt.Errorf(
			"ELF size exceeds supported reader offsets: %d",
			size,
		)
	}

	bounded := io.NewSectionReader(
		reader, 0, int64(size),
	)

	tables, err := inspectELFTables(
		bounded, size,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"ELF header tables: %w", err,
		)
	}

	file, err := elf.NewFile(bounded)
	if err != nil {
		return nil, fmt.Errorf(
			"ELF header: %w", err,
		)
	}

	if err := appendExtendedELFPrograms(
		file, bounded, size, tables,
	); err != nil {
		return nil, fmt.Errorf(
			"ELF extended program headers: %w",
			err,
		)
	}

	return file, nil
}
