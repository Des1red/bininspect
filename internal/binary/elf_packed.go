package binary

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	dynAndroidREL       elf.DynTag = 0x6000000f
	dynAndroidRELSZ     elf.DynTag = 0x60000010
	dynAndroidRELA      elf.DynTag = 0x60000011
	dynAndroidRELASZ    elf.DynTag = 0x60000012
	dynAndroidRELR      elf.DynTag = 0x6fffe000
	dynAndroidRELRSZ    elf.DynTag = 0x6fffe001
	dynAndroidRELRENT   elf.DynTag = 0x6fffe003
	dynAndroidRELRCOUNT elf.DynTag = 0x6fffe005

	elfSHTAndroidREL  elf.SectionType = 0x60000001
	elfSHTAndroidRELA elf.SectionType = 0x60000002
	elfSHTAndroidRELR elf.SectionType = 0x6fffff00

	androidGroupInfo   uint64 = 1
	androidGroupOffset uint64 = 2
	androidGroupAddend uint64 = 4
	androidHasAddend   uint64 = 8
)

type slebReader struct {
	data []byte
	pos  int
}

func (d *slebReader) next() (int64, error) {
	var value uint64

	for n := 0; n < 10; n++ {
		if d.pos == len(d.data) {
			return 0, errors.New("truncated SLEB128")
		}

		b := d.data[d.pos]
		d.pos++

		if n == 9 && b != 0x00 && b != 0x7f {
			return 0, errors.New("SLEB128 exceeds 64 bits")
		}

		value |= uint64(b&0x7f) << uint(7*n)

		if b&0x80 == 0 {
			bits := uint(7 * (n + 1))

			if bits < 64 && b&0x40 != 0 {
				value |= ^uint64(0) << bits
			}

			return int64(value), nil
		}
	}

	return 0, errors.New("SLEB128 exceeds 10 bytes")
}

func addSignedOffset(base uint64, delta int64) (uint64, error) {
	if delta >= 0 {
		if base > math.MaxUint64-uint64(delta) {
			return 0, errors.New("relocation offset overflow")
		}

		return base + uint64(delta), nil
	}

	magnitude := uint64(-(delta + 1)) + 1

	if base < magnitude {
		return 0, errors.New("relocation offset underflow")
	}

	return base - magnitude, nil
}

func addSignedAddend(base, delta int64) (int64, error) {
	if (delta > 0 && base > math.MaxInt64-delta) ||
		(delta < 0 && base < math.MinInt64-delta) {
		return 0, errors.New("relocation addend overflow")
	}

	return base + delta, nil
}

// decodeAndroidAPS2 decodes Android's SLEB128-packed relocation
// groups without executing or applying the relocations.
func decodeAndroidAPS2(
	data []byte,
	bits uint8,
	rela bool,
) ([]ELFRelocation, error) {
	if bits != 32 && bits != 64 {
		return nil, fmt.Errorf("unsupported APS2 bitness %d", bits)
	}

	if len(data) < 4 || !bytes.Equal(data[:4], []byte("APS2")) {
		return nil, errors.New(
			"invalid Android packed relocation magic (expected APS2)",
		)
	}

	decoder := slebReader{data: data[4:]}

	count, err := decoder.next()
	if err != nil {
		return nil, fmt.Errorf("APS2 relocation count: %w", err)
	}

	if count < 0 || count > int64(maxELFMetadataRecords) {
		return nil, fmt.Errorf("invalid APS2 relocation count %d", count)
	}

	initial, err := decoder.next()
	if err != nil {
		return nil, fmt.Errorf("APS2 initial offset: %w", err)
	}

	if initial < 0 {
		return nil, errors.New("negative APS2 initial offset")
	}

	offset := uint64(initial)

	if bits == 32 && offset > math.MaxUint32 {
		return nil, errors.New("APS2 initial offset exceeds ELF32 width")
	}

	result := make([]ELFRelocation, 0, int(count))

	var info uint64
	var addend int64

	for int64(len(result)) < count {
		groupSize, err := decoder.next()
		if err != nil {
			return nil, fmt.Errorf("APS2 group size: %w", err)
		}

		if groupSize <= 0 ||
			groupSize > count-int64(len(result)) {
			return nil, fmt.Errorf(
				"invalid APS2 group size %d", groupSize,
			)
		}

		flagsValue, err := decoder.next()
		if err != nil {
			return nil, fmt.Errorf("APS2 group flags: %w", err)
		}

		if flagsValue < 0 || uint64(flagsValue)&^uint64(15) != 0 {
			return nil, fmt.Errorf(
				"invalid APS2 group flags %#x", flagsValue,
			)
		}

		flags := uint64(flagsValue)

		if flags&androidGroupAddend != 0 &&
			flags&androidHasAddend == 0 {
			return nil, errors.New(
				"APS2 grouped addend without HAS_ADDEND",
			)
		}

		if !rela && flags&androidHasAddend != 0 {
			return nil, errors.New("APS2 REL contains addends")
		}

		var groupDelta int64

		if flags&androidGroupOffset != 0 {
			groupDelta, err = decoder.next()
			if err != nil {
				return nil, fmt.Errorf(
					"APS2 group offset delta: %w", err,
				)
			}
		}

		if flags&androidGroupInfo != 0 {
			value, err := decoder.next()
			if err != nil {
				return nil, fmt.Errorf(
					"APS2 group relocation info: %w", err,
				)
			}

			info = uint64(value)
		}

		if rela {
			switch flags & (androidHasAddend | androidGroupAddend) {
			case androidHasAddend | androidGroupAddend:
				delta, err := decoder.next()
				if err != nil {
					return nil, fmt.Errorf(
						"APS2 grouped addend: %w", err,
					)
				}

				addend, err = addSignedAddend(addend, delta)
				if err != nil {
					return nil, err
				}

			case 0:
				addend = 0
			}
		}

		for i := int64(0); i < groupSize; i++ {
			delta := groupDelta

			if flags&androidGroupOffset == 0 {
				delta, err = decoder.next()
				if err != nil {
					return nil, fmt.Errorf(
						"APS2 relocation offset delta: %w", err,
					)
				}
			}

			offset, err = addSignedOffset(offset, delta)
			if err != nil {
				return nil, err
			}

			if bits == 32 && offset > math.MaxUint32 {
				return nil, errors.New(
					"APS2 relocation offset exceeds ELF32 width",
				)
			}

			if flags&androidGroupInfo == 0 {
				value, err := decoder.next()
				if err != nil {
					return nil, fmt.Errorf(
						"APS2 relocation info: %w", err,
					)
				}

				info = uint64(value)
			}

			if bits == 32 && info > math.MaxUint32 {
				return nil, errors.New(
					"APS2 relocation info exceeds ELF32 width",
				)
			}

			if rela &&
				flags&androidHasAddend != 0 &&
				flags&androidGroupAddend == 0 {

				delta, err := decoder.next()
				if err != nil {
					return nil, fmt.Errorf(
						"APS2 relocation addend: %w", err,
					)
				}

				addend, err = addSignedAddend(addend, delta)
				if err != nil {
					return nil, err
				}
			}

			record := ELFRelocation{
				Section:       -1,
				Index:         len(result),
				TargetSection: -1,
				SymbolTable:   -1,
				Offset:        offset,
				HasAddend:     rela,
				Encoding:      "ANDROID_REL",
			}

			if rela {
				record.Encoding = "ANDROID_RELA"
				record.Addend = addend
			}

			if bits == 64 {
				record.SymbolIndex = uint32(info >> 32)
				record.Type = uint32(info)
			} else {
				record.SymbolIndex = uint32(info) >> 8
				record.Type = uint32(info) & 0xff
			}

			result = append(result, record)
		}
	}

	if decoder.pos != len(decoder.data) {
		return nil, errors.New("unexpected trailing APS2 data")
	}

	return result, nil
}

// decodeAndroidRELR handles the legacy Android RELR encoding.
func decodeAndroidRELR(
	data []byte,
	bits uint8,
	order binary.ByteOrder,
) ([]ELFRelocation, error) {
	if bits != 32 && bits != 64 {
		return nil, fmt.Errorf("invalid RELR bitness %d", bits)
	}

	word := uint64(bits / 8)

	if len(data)%int(word) != 0 {
		return nil, errors.New("truncated Android RELR words")
	}

	if uint64(len(data)) > maxELFMetadataBytes {
		return nil, errors.New("Android RELR table too large")
	}

	maxAddress := uint64(math.MaxUint64)
	if bits == 32 {
		maxAddress = math.MaxUint32
	}

	var result []ELFRelocation
	var base uint64
	var haveBase bool

	add := func(address uint64) error {
		if address%word != 0 ||
			address > maxAddress-(word-1) {
			return fmt.Errorf(
				"invalid Android RELR address %#x", address,
			)
		}

		if len(result) >= int(maxELFMetadataRecords) {
			return errors.New("too many Android RELR relocations")
		}

		result = append(result, ELFRelocation{
			Section:       -1,
			Index:         len(result),
			TargetSection: -1,
			SymbolTable:   -1,
			Offset:        address,
			Encoding:      "RELR",
		})

		return nil
	}

	for i := 0; i < len(data); i += int(word) {
		var value uint64

		if word == 4 {
			value = uint64(order.Uint32(data[i : i+4]))
		} else {
			value = order.Uint64(data[i : i+8])
		}

		if value&1 == 0 {
			if err := add(value); err != nil {
				return nil, err
			}

			if value > maxAddress-word {
				return nil, errors.New("Android RELR base overflow")
			}

			base = value + word
			haveBase = true
			continue
		}

		if !haveBase {
			return nil, errors.New(
				"Android RELR bitmap without base",
			)
		}

		for bit := uint64(1); bit < word*8; bit++ {
			if value&(uint64(1)<<bit) == 0 {
				continue
			}

			delta := (bit - 1) * word

			if base > maxAddress ||
				delta > maxAddress-base {
				return nil, errors.New(
					"Android RELR address overflow",
				)
			}

			if err := add(base + delta); err != nil {
				return nil, err
			}
		}

		advance := (word*8 - 1) * word

		if base > maxAddress ||
			advance > maxAddress-base {
			return nil, errors.New("Android RELR base overflow")
		}

		base += advance
	}

	return result, nil
}

// readAndroidRelocations reads packed relocations from PT_DYNAMIC.
func readAndroidRelocations(
	image *Image,
	entries []ELFDynamicEntry,
	order binary.ByteOrder,
) ([]ELFRelocation, error) {
	var result []ELFRelocation

	families := []struct {
		address elf.DynTag
		size    elf.DynTag
		rela    bool
	}{
		{dynAndroidREL, dynAndroidRELSZ, false},
		{dynAndroidRELA, dynAndroidRELASZ, true},
	}

	for _, family := range families {
		address, hasAddress, err := uniqueDynamicTag(
			entries, family.address,
		)
		if err != nil {
			return nil, err
		}

		size, hasSize, err := uniqueDynamicTag(
			entries, family.size,
		)
		if err != nil {
			return nil, err
		}

		if hasAddress != hasSize {
			return nil, fmt.Errorf(
				"incomplete %s pointer/size tags",
				family.address,
			)
		}

		if !hasAddress {
			continue
		}

		if size == 0 {
			return nil, fmt.Errorf(
				"%s has an empty packed relocation table",
				family.address,
			)
		}

		data, err := dynamicRead(image, address, size)
		if err != nil {
			return nil, err
		}

		records, err := decodeAndroidAPS2(
			data, image.Info.Bits, family.rela,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%s: %w", family.address, err,
			)
		}

		for _, record := range records {
			if err := validateAndroidRelocationTarget(
				image, record.Offset,
			); err != nil {
				return nil, err
			}

			record.Index = len(result)
			result = append(result, record)

			if len(result) > int(maxELFMetadataRecords) {
				return nil, errors.New(
					"too many Android relocations",
				)
			}
		}
	}

	address, hasAddress, err := uniqueDynamicTag(
		entries, dynAndroidRELR,
	)
	if err != nil {
		return nil, err
	}

	size, hasSize, err := uniqueDynamicTag(
		entries, dynAndroidRELRSZ,
	)
	if err != nil {
		return nil, err
	}

	entrySize, hasEntrySize, err := uniqueDynamicTag(
		entries, dynAndroidRELRENT,
	)
	if err != nil {
		return nil, err
	}

	// Android's linker ignores this historical count hint.
	_, _, err = uniqueDynamicTag(
		entries, dynAndroidRELRCOUNT,
	)
	if err != nil {
		return nil, err
	}

	if hasAddress || hasSize || hasEntrySize {
		if !hasAddress || !hasSize || !hasEntrySize {
			return nil, errors.New(
				"incomplete legacy Android RELR tags",
			)
		}

		word := uint64(image.Info.Bits / 8)

		if entrySize != word ||
			size%word != 0 ||
			size > maxELFMetadataBytes {
			return nil, errors.New(
				"invalid legacy Android RELR size/width",
			)
		}

		data, err := dynamicRead(image, address, size)
		if err != nil {
			return nil, err
		}

		records, err := decodeAndroidRELR(
			data, image.Info.Bits, order,
		)
		if err != nil {
			return nil, err
		}

		for _, record := range records {
			if err := validateAndroidRelocationTarget(
				image, record.Offset,
			); err != nil {
				return nil, err
			}

			record.Index = len(result)
			result = append(result, record)

			if len(result) > int(maxELFMetadataRecords) {
				return nil, errors.New(
					"too many Android relocations",
				)
			}
		}
	}

	return result, nil
}

func validateAndroidRelocationTarget(
	image *Image,
	address uint64,
) error {
	region, ok := image.RegionAt(address)
	if !ok {
		return fmt.Errorf(
			"relocation target %#x is unmapped", address,
		)
	}

	word := uint64(image.Info.Bits / 8)

	if word > region.MemorySize-(address-region.Address) {
		return fmt.Errorf(
			"relocation target %#x crosses memory region",
			address,
		)
	}

	return nil
}
