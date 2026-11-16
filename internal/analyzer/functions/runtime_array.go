package functions

import (
	"debug/elf"
	stdbin "encoding/binary"

	"bininspect/internal/binary"
)

type RuntimeArrayEntry struct {
	Address uint64
	Source  string
}

func RuntimeArrayEntries(
	parsed *binary.ELFResult,
) []RuntimeArrayEntry {
	if parsed == nil ||
		parsed.Image == nil ||
		parsed.Header.Type == elf.ET_REL {
		return nil
	}

	var width uint64

	switch parsed.Header.Class {
	case elf.ELFCLASS32:
		width = 4
	case elf.ELFCLASS64:
		width = 8
	default:
		return nil
	}

	var order stdbin.ByteOrder

	switch parsed.Header.Data {
	case elf.ELFDATA2LSB:
		order = stdbin.LittleEndian
	case elf.ELFDATA2MSB:
		order = stdbin.BigEndian
	default:
		return nil
	}

	var entries []RuntimeArrayEntry
	seen := make(map[uint64]bool)

	for _, section := range parsed.Sections {
		source := ""

		switch section.Name {
		case ".preinit_array":
			source = "preinit-array"
		case ".init_array":
			source = "init-array"
		case ".fini_array":
			source = "fini-array"
		default:
			continue
		}

		// Bound reads from malformed or untrusted ELF files.
		if section.Size == 0 ||
			section.Size > 1<<20 ||
			section.Size%width != 0 {
			continue
		}

		data, err := parsed.Image.ReadVirtual(
			section.Addr,
			section.Size,
		)
		if err != nil {
			continue
		}

		for off := uint64(0); off+width <= uint64(len(data)); off += width {
			var address uint64

			if width == 8 {
				address = order.Uint64(data[off : off+8])
			} else {
				address = uint64(
					order.Uint32(data[off : off+4]),
				)
			}

			// Skip empty or duplicate entries.
			if address == 0 || seen[address] {
				continue
			}

			seen[address] = true

			entries = append(entries, RuntimeArrayEntry{
				Address: address,
				Source:  source,
			})
		}
	}

	return entries
}
