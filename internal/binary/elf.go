package binary

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
)

const maxELFHeaderTableBytes uint64 = 32 << 20

var (
	ErrUnsupportedELFType = errors.New(
		"unsupported ELF file type",
	)
	ErrUnsupportedELFMachine = errors.New(
		"unsupported ELF machine/class combination",
	)
)

// ParseELF loads executable and shared-library ELF images.
// The caller owns reader and must keep it open while using the Image.
func ParseELF(reader io.ReaderAt, fileSize uint64) (*Image, error) {
	if reader == nil {
		return nil, errors.New("nil ELF reader")
	}
	if fileSize > math.MaxInt64 {
		return nil, fmt.Errorf(
			"ELF size %d exceeds supported reader offsets",
			fileSize,
		)
	}

	bounded := io.NewSectionReader(reader, 0, int64(fileSize))

	tables, err := inspectELFTables(bounded, fileSize)
	if err != nil {
		return nil, fmt.Errorf("ELF header: %w", err)
	}

	file, err := elf.NewFile(bounded)
	if err != nil {
		return nil, fmt.Errorf("parsing ELF: %w", err)
	}

	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return nil, fmt.Errorf(
			"%w: %s",
			ErrUnsupportedELFType,
			file.Type,
		)
	}

	info, err := elfImageInfo(file)
	if err != nil {
		return nil, err
	}

	if err := appendExtendedELFPrograms(
		file, bounded, fileSize, tables,
	); err != nil {
		return nil, fmt.Errorf("ELF program headers: %w", err)
	}

	regions := make([]Region, 0, len(file.Progs))

	for i, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}

		if prog.Memsz == 0 {
			if prog.Filesz != 0 {
				return nil, fmt.Errorf(
					"PT_LOAD[%d]: nonempty file data has zero memory size",
					i,
				)
			}
			continue
		}

		if prog.Align > 1 {
			if prog.Align&(prog.Align-1) != 0 {
				return nil, fmt.Errorf(
					"PT_LOAD[%d]: alignment %d is not a power of two",
					i,
					prog.Align,
				)
			}

			if prog.Vaddr%prog.Align != prog.Off%prog.Align {
				return nil, fmt.Errorf(
					"PT_LOAD[%d]: offset and virtual address disagree modulo alignment",
					i,
				)
			}
		}

		if info.Bits == 32 &&
			(prog.Vaddr >= uint64(1)<<32 ||
				prog.Memsz > (uint64(1)<<32)-prog.Vaddr) {
			return nil, fmt.Errorf(
				"PT_LOAD[%d]: mapping exceeds 32-bit virtual address space",
				i,
			)
		}

		var permissions Permissions

		if prog.Flags&elf.PF_R != 0 {
			permissions |= PermRead
		}
		if prog.Flags&elf.PF_W != 0 {
			permissions |= PermWrite
		}
		if prog.Flags&elf.PF_X != 0 {
			permissions |= PermExecute
		}

		regions = append(regions, Region{
			Name:        fmt.Sprintf("PT_LOAD[%d]", i),
			Address:     prog.Vaddr,
			MemorySize:  prog.Memsz,
			FileOffset:  prog.Off,
			FileSize:    prog.Filesz,
			Permissions: permissions,
		})
	}
	regions, err = normalizeELFLoadRegions(regions)
	if err != nil {
		return nil, fmt.Errorf("ELF load mappings: %w", err)
	}

	image, err := NewImage(bounded, fileSize, info, regions)
	if err != nil {
		return nil, fmt.Errorf("ELF loadable segments: %w", err)
	}

	if info.Entry != 0 {
		region, ok := image.RegionAt(info.Entry)

		if !ok ||
			region.Permissions&PermExecute == 0 ||
			info.Entry-region.Address >= region.FileSize {
			return nil, fmt.Errorf(
				"ELF entry 0x%x is not in a file-backed executable segment",
				info.Entry,
			)
		}
	}

	return image, nil
}

func elfImageInfo(file *elf.File) (Info, error) {
	info := Info{
		Format: FormatELF,
		Entry:  file.Entry,
	}

	switch file.Class {
	case elf.ELFCLASS32:
		info.Bits = 32
	case elf.ELFCLASS64:
		info.Bits = 64
	default:
		return Info{}, fmt.Errorf(
			"unsupported ELF class: %s",
			file.Class,
		)
	}

	switch file.Data {
	case elf.ELFDATA2LSB:
		info.Endianness = LittleEndian
	case elf.ELFDATA2MSB:
		info.Endianness = BigEndian
	default:
		return Info{}, fmt.Errorf(
			"unsupported ELF data encoding: %s",
			file.Data,
		)
	}

	switch file.Machine {
	case elf.EM_386:
		if info.Bits == 32 && info.Endianness == LittleEndian {
			info.Architecture = ArchX86
		}

	case elf.EM_X86_64:
		if info.Bits == 64 && info.Endianness == LittleEndian {
			info.Architecture = ArchX8664
		}

	case elf.EM_ARM:
		if info.Bits == 32 {
			info.Architecture = ArchARM
		}

	case elf.EM_AARCH64:
		if info.Bits == 64 {
			info.Architecture = ArchARM64
		}

	case elf.EM_RISCV:
		if info.Bits == 64 && info.Endianness == LittleEndian {
			info.Architecture = ArchRISCV64
		}
	}

	if info.Architecture == "" {
		return Info{}, fmt.Errorf(
			"%w: machine=%s class=%s encoding=%s",
			ErrUnsupportedELFMachine,
			file.Machine,
			file.Class,
			file.Data,
		)
	}

	return info, nil
}
