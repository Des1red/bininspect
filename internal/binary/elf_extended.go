package binary

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

var ErrInvalidELFExtendedNumbering = errors.New(
	"invalid ELF extended numbering",
)

type elfTables struct {
	order binary.ByteOrder
	class elf.Class

	programOffset    uint64
	programEntrySize uint64
	programCount     uint64

	sectionOffset    uint64
	sectionEntrySize uint64
	sectionCount     uint64
	namesIndex       uint64

	extendedPrograms bool
}

func inspectELFTables(
	reader io.ReaderAt,
	size uint64,
) (elfTables, error) {
	var result elfTables

	if reader == nil || size < 16 {
		return result, errors.New("truncated ELF identification")
	}

	var ident [16]byte

	if _, err := reader.ReadAt(ident[:], 0); err != nil {
		return result, err
	}

	if string(ident[:4]) != "\x7fELF" {
		return result, errors.New("invalid ELF magic")
	}

	if ident[6] != byte(elf.EV_CURRENT) {
		return result, fmt.Errorf(
			"invalid ELF identification version %d",
			ident[6],
		)
	}

	var headerSize, phSize, shSize uint64

	switch elf.Class(ident[4]) {
	case elf.ELFCLASS32:
		result.class = elf.ELFCLASS32
		headerSize = 52
		phSize = 32
		shSize = 40

	case elf.ELFCLASS64:
		result.class = elf.ELFCLASS64
		headerSize = 64
		phSize = 56
		shSize = 64

	default:
		return result, fmt.Errorf(
			"unsupported ELF class %d", ident[4],
		)
	}

	switch elf.Data(ident[5]) {
	case elf.ELFDATA2LSB:
		result.order = binary.LittleEndian

	case elf.ELFDATA2MSB:
		result.order = binary.BigEndian

	default:
		return result, fmt.Errorf(
			"unsupported ELF encoding %d", ident[5],
		)
	}

	if size < headerSize {
		return result, errors.New("truncated ELF header")
	}

	var hdr [64]byte

	if _, err := reader.ReadAt(hdr[:headerSize], 0); err != nil {
		return result, err
	}

	var declaredSize, rawPrograms, rawSections, rawNames uint16

	bo := result.order

	if result.class == elf.ELFCLASS32 {
		result.programOffset = uint64(bo.Uint32(hdr[28:32]))
		result.sectionOffset = uint64(bo.Uint32(hdr[32:36]))

		declaredSize = bo.Uint16(hdr[40:42])
		result.programEntrySize = uint64(bo.Uint16(hdr[42:44]))
		rawPrograms = bo.Uint16(hdr[44:46])
		result.sectionEntrySize = uint64(bo.Uint16(hdr[46:48]))
		rawSections = bo.Uint16(hdr[48:50])
		rawNames = bo.Uint16(hdr[50:52])
	} else {
		result.programOffset = bo.Uint64(hdr[32:40])
		result.sectionOffset = bo.Uint64(hdr[40:48])

		declaredSize = bo.Uint16(hdr[52:54])
		result.programEntrySize = uint64(bo.Uint16(hdr[54:56]))
		rawPrograms = bo.Uint16(hdr[56:58])
		result.sectionEntrySize = uint64(bo.Uint16(hdr[58:60]))
		rawSections = bo.Uint16(hdr[60:62])
		rawNames = bo.Uint16(hdr[62:64])
	}

	if uint64(declaredSize) < headerSize ||
		uint64(declaredSize) > size {
		return result, fmt.Errorf(
			"invalid ELF header size %d", declaredSize,
		)
	}

	if result.sectionOffset == 0 &&
		(rawSections != 0 || rawNames != 0) {
		return result, errors.New(
			"section header table absent but count or name index is present",
		)
	}

	result.programCount = uint64(rawPrograms)
	result.sectionCount = uint64(rawSections)
	result.namesIndex = uint64(rawNames)

	needZero := rawPrograms == 0xffff ||
		(result.sectionOffset != 0 && rawSections == 0) ||
		rawNames == 0xffff

	if needZero {
		if result.sectionOffset == 0 {
			return result, fmt.Errorf(
				"%w: missing section header zero",
				ErrInvalidELFExtendedNumbering,
			)
		}

		if err := checkELFHeaderTable(
			"section",
			result.sectionOffset,
			1,
			result.sectionEntrySize,
			shSize,
			size,
		); err != nil {
			return result, err
		}

		var sh [64]byte

		if _, err := reader.ReadAt(
			sh[:shSize],
			int64(result.sectionOffset),
		); err != nil {
			return result, err
		}

		if bo.Uint32(sh[4:8]) != uint32(elf.SHT_NULL) {
			return result, fmt.Errorf(
				"%w: section zero is not SHT_NULL",
				ErrInvalidELFExtendedNumbering,
			)
		}

		var zeroSize uint64
		var zeroLink, zeroInfo uint32

		if result.class == elf.ELFCLASS32 {
			zeroSize = uint64(bo.Uint32(sh[20:24]))
			zeroLink = bo.Uint32(sh[24:28])
			zeroInfo = bo.Uint32(sh[28:32])
		} else {
			zeroSize = bo.Uint64(sh[32:40])
			zeroLink = bo.Uint32(sh[40:44])
			zeroInfo = bo.Uint32(sh[44:48])
		}

		// Extended program-header count: sh_info.
		if rawPrograms == 0xffff {
			result.extendedPrograms = true
			result.programCount = uint64(zeroInfo)

			if result.programCount < 0xffff {
				return result, fmt.Errorf(
					"%w: invalid program count %d",
					ErrInvalidELFExtendedNumbering,
					result.programCount,
				)
			}
		}

		// Extended section count: sh_size.
		if rawSections == 0 {
			result.sectionCount = zeroSize

			if result.sectionCount < 0xff00 {
				return result, fmt.Errorf(
					"%w: invalid section count %d",
					ErrInvalidELFExtendedNumbering,
					result.sectionCount,
				)
			}
		}

		// Extended section-name index: sh_link.
		if rawNames == 0xffff {
			result.namesIndex = uint64(zeroLink)

			if result.namesIndex < 0xff00 {
				return result, fmt.Errorf(
					"%w: invalid section-name index %d",
					ErrInvalidELFExtendedNumbering,
					result.namesIndex,
				)
			}
		}
	}

	if result.namesIndex != 0 &&
		result.namesIndex >= result.sectionCount {
		return result, fmt.Errorf(
			"invalid section-name index %d (sections %d)",
			result.namesIndex,
			result.sectionCount,
		)
	}

	if err := checkELFHeaderTable(
		"program",
		result.programOffset,
		result.programCount,
		result.programEntrySize,
		phSize,
		size,
	); err != nil {
		return result, err
	}

	if err := checkELFHeaderTable(
		"section",
		result.sectionOffset,
		result.sectionCount,
		result.sectionEntrySize,
		shSize,
		size,
	); err != nil {
		return result, err
	}

	return result, nil
}

func preflightELF(reader io.ReaderAt, size uint64) error {
	_, err := inspectELFTables(reader, size)
	return err
}

func checkELFHeaderTable(
	name string,
	offset, count, entrySize, minEntrySize, fileSize uint64,
) error {
	if count == 0 {
		return nil
	}

	if offset == 0 {
		return fmt.Errorf(
			"%s header table has nonzero count but zero offset",
			name,
		)
	}

	if entrySize < minEntrySize {
		return fmt.Errorf(
			"%s header entry size %d smaller than %d",
			name, entrySize, minEntrySize,
		)
	}

	if count > maxELFHeaderTableBytes/entrySize {
		return fmt.Errorf(
			"%s header table exceeds %d-byte metadata limit",
			name, maxELFHeaderTableBytes,
		)
	}

	total := count * entrySize

	if offset > fileSize || total > fileSize-offset {
		return fmt.Errorf(
			"%s header table extends beyond file",
			name,
		)
	}

	return nil
}

func appendExtendedELFPrograms(
	file *elf.File,
	reader io.ReaderAt,
	size uint64,
	tables elfTables,
) error {
	if !tables.extendedPrograms {
		return nil
	}

	parsed := uint64(len(file.Progs))

	if parsed > tables.programCount {
		return fmt.Errorf(
			"extended ELF: parsed %d program headers, expected %d",
			parsed,
			tables.programCount,
		)
	}

	if parsed == tables.programCount {
		return nil
	}

	var hdr [56]byte

	for i := parsed; i < tables.programCount; i++ {
		off := tables.programOffset + i*tables.programEntrySize

		headerSize := uint64(56)
		if tables.class == elf.ELFCLASS32 {
			headerSize = 32
		}

		if _, err := reader.ReadAt(
			hdr[:headerSize], int64(off),
		); err != nil {
			return fmt.Errorf(
				"reading program header %d: %w", i, err,
			)
		}

		var p elf.ProgHeader
		bo := tables.order

		if tables.class == elf.ELFCLASS32 {
			p.Type = elf.ProgType(bo.Uint32(hdr[0:4]))
			p.Off = uint64(bo.Uint32(hdr[4:8]))
			p.Vaddr = uint64(bo.Uint32(hdr[8:12]))
			p.Paddr = uint64(bo.Uint32(hdr[12:16]))
			p.Filesz = uint64(bo.Uint32(hdr[16:20]))
			p.Memsz = uint64(bo.Uint32(hdr[20:24]))
			p.Flags = elf.ProgFlag(bo.Uint32(hdr[24:28]))
			p.Align = uint64(bo.Uint32(hdr[28:32]))
		} else {
			p.Type = elf.ProgType(bo.Uint32(hdr[0:4]))
			p.Flags = elf.ProgFlag(bo.Uint32(hdr[4:8]))
			p.Off = bo.Uint64(hdr[8:16])
			p.Vaddr = bo.Uint64(hdr[16:24])
			p.Paddr = bo.Uint64(hdr[24:32])
			p.Filesz = bo.Uint64(hdr[32:40])
			p.Memsz = bo.Uint64(hdr[40:48])
			p.Align = bo.Uint64(hdr[48:56])
		}

		if p.Filesz > 0 &&
			(p.Off > size || p.Filesz > size-p.Off) {
			return fmt.Errorf(
				"program header %d extends beyond file", i,
			)
		}

		if p.Off > math.MaxInt64 || p.Filesz > math.MaxInt64 {
			return fmt.Errorf(
				"program header %d offset too large", i,
			)
		}

		file.Progs = append(file.Progs, &elf.Prog{
			ProgHeader: p,
			ReaderAt: io.NewSectionReader(
				reader, int64(p.Off), int64(p.Filesz),
			),
		})
	}

	return nil
}
