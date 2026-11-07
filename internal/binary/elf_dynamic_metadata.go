package binary

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	dynRelrSz  elf.DynTag = 35
	dynRelr    elf.DynTag = 36
	dynRelrEnt elf.DynTag = 37
)

type ELFDynamicMetadata struct {
	ELFMetadata

	SymbolCountSource   string
	SymbolCountComplete bool
	Warnings            []string
}

// ParseELFDynamicMetadata recovers dynamic symbols and relocations
// from program headers, even when section headers are absent.
// It does not apply relocations or execute the binary.
func ParseELFDynamicMetadata(
	reader io.ReaderAt,
	fileSize uint64,
) (ELFDynamicMetadata, error) {
	var out ELFDynamicMetadata

	image, err := ParseELF(reader, fileSize)
	if err != nil {
		return out, err
	}

	dyn, err := ParseELFDynamic(reader, fileSize)
	if err != nil {
		return out, err
	}

	if !dyn.Present {
		return out, nil
	}

	var bo binary.ByteOrder = binary.LittleEndian

	if image.Info.Endianness == BigEndian {
		bo = binary.BigEndian
	}

	// Decode relocations first so referenced symbol indices
	// can establish a minimum symbol count when required.
	relocations, err := readDynamicRelocations(
		image,
		dyn.Entries,
		bo,
	)
	if err != nil {
		return out, err
	}

	out.Relocations = relocations

	symbolAddress, hasSymbols, err := uniqueDynamicTag(
		dyn.Entries,
		elf.DT_SYMTAB,
	)
	if err != nil {
		return out, err
	}

	if !hasSymbols {
		for _, relocation := range relocations {
			if relocation.Encoding != "RELR" &&
				relocation.SymbolIndex != 0 {
				return out, fmt.Errorf(
					"relocation references symbol %d without DT_SYMTAB",
					relocation.SymbolIndex,
				)
			}
		}

		return out, nil
	}

	symbolSize := uint64(16)

	if image.Info.Bits == 64 {
		symbolSize = 24
	}

	entrySize, exists, err := uniqueDynamicTag(
		dyn.Entries,
		elf.DT_SYMENT,
	)
	if err != nil {
		return out, err
	}

	if !exists || entrySize != symbolSize {
		return out, fmt.Errorf(
			"DT_SYMENT must be %d for ELF%d",
			symbolSize,
			image.Info.Bits,
		)
	}

	count, source, complete, err := dynamicSymbolCount(
		image,
		dyn.Entries,
		bo,
	)
	if err != nil {
		return out, err
	}

	var minimum uint64

	for _, relocation := range relocations {
		if relocation.Encoding == "RELR" {
			continue
		}

		required := uint64(relocation.SymbolIndex) + 1

		if required > minimum {
			minimum = required
		}
	}

	if complete && minimum > count {
		return out, fmt.Errorf(
			"relocation references symbol outside %s table: %d >= %d",
			source,
			minimum-1,
			count,
		)
	}

	if !complete && count < minimum {
		count = minimum
	}

	out.SymbolCountSource = source
	out.SymbolCountComplete = complete

	if !complete {
		out.Warnings = append(
			out.Warnings,
			"Dynamic symbol count is a lower bound; unreferenced symbols may be absent.",
		)
	}

	if count == 0 {
		out.Warnings = append(
			out.Warnings,
			"DT_SYMTAB exists but its complete symbol count could not be established.",
		)

		return out, nil
	}

	if count > maxELFMetadataRecords ||
		count > maxELFMetadataBytes/symbolSize {
		return out, fmt.Errorf(
			"dynamic symbol count %d exceeds configured limit",
			count,
		)
	}

	strAddress, hasStrings, err := uniqueDynamicTag(
		dyn.Entries,
		elf.DT_STRTAB,
	)
	if err != nil {
		return out, err
	}

	strSize, hasStrSize, err := uniqueDynamicTag(
		dyn.Entries,
		elf.DT_STRSZ,
	)
	if err != nil {
		return out, err
	}

	if !hasStrings || !hasStrSize ||
		strSize == 0 || strSize > maxELFMetadataBytes {
		return out, errors.New(
			"DT_SYMTAB requires bounded DT_STRTAB and DT_STRSZ",
		)
	}

	stringTable, err := dynamicRead(
		image,
		strAddress,
		strSize,
	)
	if err != nil {
		return out, fmt.Errorf("DT_STRTAB: %w", err)
	}

	data, err := dynamicRead(
		image,
		symbolAddress,
		count*symbolSize,
	)
	if err != nil {
		return out, fmt.Errorf("DT_SYMTAB: %w", err)
	}

	shndxAddress, hasShndx, err := uniqueDynamicTag(
		dyn.Entries,
		elf.DT_SYMTAB_SHNDX,
	)
	if err != nil {
		return out, err
	}

	var extendedIndices []byte

	if hasShndx {
		extendedIndices, err = dynamicRead(
			image,
			shndxAddress,
			count*4,
		)
		if err != nil {
			return out, fmt.Errorf(
				"DT_SYMTAB_SHNDX: %w",
				err,
			)
		}
	}

	out.Symbols = make([]ELFSymbol, 0, int(count))

	for i := uint64(0); i < count; i++ {
		entry := data[i*symbolSize : (i+1)*symbolSize]

		var nameOffset uint32
		var value, size uint64
		var info, other byte
		var section uint16

		if symbolSize == 16 {
			nameOffset = bo.Uint32(entry[0:4])
			value = uint64(bo.Uint32(entry[4:8]))
			size = uint64(bo.Uint32(entry[8:12]))
			info = entry[12]
			other = entry[13]
			section = bo.Uint16(entry[14:16])
		} else {
			nameOffset = bo.Uint32(entry[0:4])
			info = entry[4]
			other = entry[5]
			section = bo.Uint16(entry[6:8])
			value = bo.Uint64(entry[8:16])
			size = bo.Uint64(entry[16:24])
		}

		name, err := elfSymbolName(
			stringTable,
			nameOffset,
		)
		if err != nil {
			return out, fmt.Errorf(
				"dynamic symbol %d: %w",
				i,
				err,
			)
		}

		sectionIndex := uint32(section)

		if section == uint16(elf.SHN_XINDEX) {
			if !hasShndx {
				return out, fmt.Errorf(
					"dynamic symbol %d requires DT_SYMTAB_SHNDX",
					i,
				)
			}

			sectionIndex = bo.Uint32(
				extendedIndices[i*4 : i*4+4],
			)
		}

		out.Symbols = append(out.Symbols, ELFSymbol{
			TableSection: -1,
			Index:        uint32(i),
			Name:         name,
			Value:        value,
			Size:         size,
			Binding:      elf.ST_BIND(info),
			Type:         elf.ST_TYPE(info),
			Visibility:   elf.ST_VISIBILITY(other),
			SectionIndex: sectionIndex,
		})
	}

	// Resolve symbol names for REL and RELA records.
	// RELR records do not reference symbols.
	for i := range out.Relocations {
		relocation := &out.Relocations[i]

		if relocation.Encoding == "RELR" {
			continue
		}

		if uint64(relocation.SymbolIndex) >=
			uint64(len(out.Symbols)) {
			return out, fmt.Errorf(
				"relocation %d: symbol index %d is unavailable",
				i,
				relocation.SymbolIndex,
			)
		}

		relocation.SymbolName =
			out.Symbols[relocation.SymbolIndex].Name
	}

	return out, nil
}

// dynamicRead performs bounded virtual-memory reads and supports
// file-backed metadata spanning adjacent mapped regions.
func dynamicRead(
	image *Image,
	address uint64,
	size uint64,
) ([]byte, error) {
	if size > maxELFMetadataBytes {
		return nil, fmt.Errorf(
			"metadata read %d exceeds limit",
			size,
		)
	}

	if address > math.MaxUint64-size {
		return nil, errors.New(
			"virtual address overflow",
		)
	}

	result := make([]byte, int(size))

	for pos := uint64(0); pos < size; {
		current := address + pos

		region, ok := image.RegionAt(current)
		if !ok {
			return nil, fmt.Errorf(
				"unmapped metadata at %#x",
				current,
			)
		}

		delta := current - region.Address

		if delta >= region.FileSize {
			return nil, fmt.Errorf(
				"metadata at %#x is not file-backed",
				current,
			)
		}

		step := size - pos

		if available := region.FileSize - delta; step > available {
			step = available
		}

		if step > MaxReadSize {
			step = MaxReadSize
		}

		data, err := image.ReadVirtual(
			current,
			step,
		)
		if err != nil {
			return nil, err
		}

		copy(
			result[int(pos):int(pos+step)],
			data,
		)

		pos += step
	}

	return result, nil
}

func dynamicSymbolCount(
	image *Image,
	entries []ELFDynamicEntry,
	bo binary.ByteOrder,
) (uint64, string, bool, error) {
	hashAddress, hasHash, err := uniqueDynamicTag(
		entries,
		elf.DT_HASH,
	)
	if err != nil {
		return 0, "", false, err
	}

	gnuAddress, hasGNU, err := uniqueDynamicTag(
		entries,
		elf.DT_GNU_HASH,
	)
	if err != nil {
		return 0, "", false, err
	}

	var count, gnuCount uint64

	if hasHash {
		header, err := dynamicRead(
			image,
			hashAddress,
			8,
		)
		if err != nil {
			return 0, "", false, fmt.Errorf(
				"DT_HASH: %w",
				err,
			)
		}

		buckets := uint64(
			bo.Uint32(header[0:4]),
		)
		symbols := uint64(
			bo.Uint32(header[4:8]),
		)

		if buckets == 0 || symbols == 0 ||
			buckets+symbols > maxELFMetadataRecords ||
			buckets+symbols >
				(maxELFMetadataBytes-8)/4 {
			return 0, "", false, errors.New(
				"invalid DT_HASH bucket/chain count",
			)
		}

		table, err := dynamicRead(
			image,
			hashAddress,
			8+(buckets+symbols)*4,
		)
		if err != nil {
			return 0, "", false, fmt.Errorf(
				"DT_HASH data: %w",
				err,
			)
		}

		for i := uint64(0); i < buckets+symbols; i++ {
			value := uint64(
				bo.Uint32(
					table[8+i*4 : 12+i*4],
				),
			)

			if value >= symbols {
				return 0, "", false, fmt.Errorf(
					"DT_HASH index %d outside symbol count %d",
					value,
					symbols,
				)
			}
		}

		count = symbols
	}

	if hasGNU {
		gnuCount, err = gnuHashCount(
			image,
			gnuAddress,
			bo,
		)
		if err != nil {
			return 0, "", false, err
		}

		if hasHash && gnuCount > count {
			return 0, "", false, fmt.Errorf(
				"DT_GNU_HASH references %d symbols, DT_HASH has %d",
				gnuCount,
				count,
			)
		}
	}

	if hasHash {
		return count, "DT_HASH", true, nil
	}

	if hasGNU {
		return gnuCount, "DT_GNU_HASH", false, nil
	}

	return 0, "unavailable", false, nil
}

func gnuHashCount(
	image *Image,
	address uint64,
	bo binary.ByteOrder,
) (uint64, error) {
	header, err := dynamicRead(
		image,
		address,
		16,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"DT_GNU_HASH: %w",
			err,
		)
	}

	buckets := uint64(
		bo.Uint32(header[0:4]),
	)
	offset := uint64(
		bo.Uint32(header[4:8]),
	)
	bloom := uint64(
		bo.Uint32(header[8:12]),
	)

	if buckets == 0 || bloom == 0 ||
		buckets > maxELFMetadataRecords ||
		offset > maxELFMetadataRecords {
		return 0, errors.New(
			"invalid GNU hash counts",
		)
	}

	word := uint64(image.Info.Bits) / 8

	if bloom > (maxELFMetadataBytes-16)/word {
		return 0, errors.New(
			"GNU hash bloom filter too large",
		)
	}

	bucketsOffset := uint64(16) + bloom*word

	if buckets >
		(maxELFMetadataBytes-bucketsOffset)/4 {
		return 0, errors.New(
			"GNU hash bucket table too large",
		)
	}

	if address > math.MaxUint64-bucketsOffset ||
		address+bucketsOffset >
			math.MaxUint64-buckets*4 {
		return 0, errors.New(
			"GNU hash address overflow",
		)
	}

	bucketData, err := dynamicRead(
		image,
		address+bucketsOffset,
		buckets*4,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"GNU hash buckets: %w",
			err,
		)
	}

	chainsStart := address +
		bucketsOffset +
		buckets*4

	region, ok := image.RegionAt(chainsStart)
	if !ok {
		return 0, errors.New(
			"GNU hash chains are unmapped",
		)
	}

	delta := chainsStart - region.Address

	if delta > region.FileSize {
		return 0, errors.New(
			"GNU hash chains are not file-backed",
		)
	}

	chainBytes := region.FileSize - delta

	if chainBytes > maxELFMetadataRecords*4 {
		chainBytes = maxELFMetadataRecords * 4
	}

	if chainBytes > maxELFMetadataBytes {
		chainBytes = maxELFMetadataBytes
	}

	chainBytes &= ^uint64(3)

	chains, err := dynamicRead(
		image,
		chainsStart,
		chainBytes,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"GNU hash chains: %w",
			err,
		)
	}

	maximum := offset

	for i := uint64(0); i < buckets; i++ {
		index := uint64(
			bo.Uint32(
				bucketData[i*4 : i*4+4],
			),
		)

		if index == 0 {
			continue
		}

		if index < offset {
			return 0, fmt.Errorf(
				"GNU hash bucket %d points below symoffset %d",
				index,
				offset,
			)
		}

		for {
			if index >= maxELFMetadataRecords {
				return 0, errors.New(
					"GNU hash symbol index limit exceeded",
				)
			}

			chainIndex := index - offset

			if chainIndex >=
				uint64(len(chains))/4 {
				return 0, errors.New(
					"unterminated GNU hash chain",
				)
			}

			value := bo.Uint32(
				chains[chainIndex*4 : chainIndex*4+4],
			)

			index++

			if index > maximum {
				maximum = index
			}

			if value&1 != 0 {
				break
			}
		}
	}

	return maximum, nil
}
