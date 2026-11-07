package binary

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

func readDynamicRelocations(
	image *Image,
	entries []ELFDynamicEntry,
	bo binary.ByteOrder,
) ([]ELFRelocation, error) {
	var all []ELFRelocation

	seen := make(map[uint64]struct {
		width uint64
		rela  bool
	})

	// DT_JMPREL may reference records already covered by
	// DT_REL or DT_RELA. Avoid recording the same entry twice.
	parse := func(
		name string,
		address, size, entrySize uint64,
		rela bool,
	) error {
		expected := uint64(8)

		if rela {
			expected = 12
		}

		if image.Info.Bits == 64 {
			expected = 16

			if rela {
				expected = 24
			}
		}

		if entrySize != expected ||
			size%entrySize != 0 {
			return fmt.Errorf(
				"%s: invalid entry size or count",
				name,
			)
		}

		if size == 0 {
			return nil
		}

		if size > maxELFMetadataBytes ||
			size/entrySize > maxELFMetadataRecords {
			return fmt.Errorf(
				"%s: relocation table too large",
				name,
			)
		}

		data, err := dynamicRead(
			image,
			address,
			size,
		)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		for i := uint64(0); i < size; i += entrySize {
			position := address + i

			if prior, exists := seen[position]; exists {
				if prior.width != entrySize ||
					prior.rela != rela {
					return fmt.Errorf(
						"conflicting relocation encodings at %#x",
						position,
					)
				}

				continue
			}

			seen[position] = struct {
				width uint64
				rela  bool
			}{entrySize, rela}

			record := data[i : i+entrySize]

			var offset, info uint64
			var addend int64

			if image.Info.Bits == 32 {
				offset = uint64(
					bo.Uint32(record[0:4]),
				)
				info = uint64(
					bo.Uint32(record[4:8]),
				)

				if rela {
					addend = int64(int32(
						bo.Uint32(record[8:12]),
					))
				}
			} else {
				offset = bo.Uint64(record[0:8])
				info = bo.Uint64(record[8:16])

				if rela {
					addend = int64(
						bo.Uint64(record[16:24]),
					)
				}
			}

			var symbolIndex, typ uint32

			if image.Info.Bits == 32 {
				symbolIndex = uint32(info) >> 8
				typ = uint32(info) & 0xff
			} else {
				symbolIndex = uint32(info >> 32)
				typ = uint32(info)
			}

			// Dynamic relocation offsets refer to virtual
			// memory, not file offsets.
			if _, ok := image.RegionAt(offset); !ok {
				return fmt.Errorf(
					"%s relocation at %#x targets unmapped address %#x",
					name,
					position,
					offset,
				)
			}

			all = append(all, ELFRelocation{
				Section:       -1,
				Index:         len(all),
				TargetSection: -1,
				SymbolTable:   -1,
				SymbolIndex:   symbolIndex,
				Offset:        offset,
				Type:          typ,
				Addend:        addend,
				HasAddend:     rela,
				Encoding:      name,
			})

			if len(all) > int(maxELFMetadataRecords) {
				return errors.New(
					"too many dynamic relocations",
				)
			}
		}

		return nil
	}

	families := []struct {
		tag  elf.DynTag
		size elf.DynTag
		ent  elf.DynTag
		name string
		rela bool
	}{
		{
			elf.DT_REL,
			elf.DT_RELSZ,
			elf.DT_RELENT,
			"REL",
			false,
		},
		{
			elf.DT_RELA,
			elf.DT_RELASZ,
			elf.DT_RELAENT,
			"RELA",
			true,
		},
	}

	for _, family := range families {
		address, hasAddress, err := uniqueDynamicTag(
			entries, family.tag,
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

		entrySize, hasEntry, err := uniqueDynamicTag(
			entries, family.ent,
		)
		if err != nil {
			return nil, err
		}

		if !hasAddress && !hasSize {
			continue
		}

		if !hasSize ||
			(size > 0 && (!hasAddress || !hasEntry)) {
			return nil, fmt.Errorf(
				"incomplete %s dynamic relocation tags",
				family.name,
			)
		}

		if size == 0 {
			continue
		}

		if err := parse(
			family.name,
			address,
			size,
			entrySize,
			family.rela,
		); err != nil {
			return nil, err
		}
	}

	pltAddress, hasPLT, err := uniqueDynamicTag(
		entries, elf.DT_JMPREL,
	)
	if err != nil {
		return nil, err
	}

	pltSize, hasPLTSize, err := uniqueDynamicTag(
		entries, elf.DT_PLTRELSZ,
	)
	if err != nil {
		return nil, err
	}

	pltKind, hasPLTKind, err := uniqueDynamicTag(
		entries, elf.DT_PLTREL,
	)
	if err != nil {
		return nil, err
	}

	if hasPLT || hasPLTSize || hasPLTKind {
		if !hasPLTSize ||
			(pltSize > 0 && (!hasPLT || !hasPLTKind)) {
			return nil, errors.New(
				"incomplete JMPREL dynamic tags",
			)
		}

		if pltSize > 0 {
			var entryTag elf.DynTag
			var rela bool

			switch elf.DynTag(pltKind) {
			case elf.DT_REL:
				entryTag = elf.DT_RELENT

			case elf.DT_RELA:
				entryTag = elf.DT_RELAENT
				rela = true

			default:
				return nil, fmt.Errorf(
					"invalid DT_PLTREL value %d",
					pltKind,
				)
			}

			entrySize, found, err := uniqueDynamicTag(
				entries, entryTag,
			)
			if err != nil {
				return nil, err
			}

			if !found {
				return nil, fmt.Errorf(
					"missing %s for JMPREL",
					entryTag,
				)
			}

			if err := parse(
				"JMPREL",
				pltAddress,
				pltSize,
				entrySize,
				rela,
			); err != nil {
				return nil, err
			}
		}
	}

	relrAddress, hasRELR, err := uniqueDynamicTag(
		entries, dynRelr,
	)
	if err != nil {
		return nil, err
	}

	relrSize, hasRELRSize, err := uniqueDynamicTag(
		entries, dynRelrSz,
	)
	if err != nil {
		return nil, err
	}

	relrEntry, hasRELREntry, err := uniqueDynamicTag(
		entries, dynRelrEnt,
	)
	if err != nil {
		return nil, err
	}

	if hasRELR || hasRELRSize || hasRELREntry {
		if !hasRELRSize ||
			(relrSize > 0 && (!hasRELR || !hasRELREntry)) {
			return nil, errors.New(
				"incomplete RELR dynamic tags",
			)
		}

		if relrSize > 0 {
			word := uint64(image.Info.Bits / 8)

			if relrEntry != word ||
				relrSize%word != 0 ||
				relrSize > maxELFMetadataBytes {
				return nil, errors.New(
					"invalid RELR size or entry width",
				)
			}

			data, err := dynamicRead(
				image, relrAddress, relrSize,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"DT_RELR: %w",
					err,
				)
			}

			var base uint64
			var haveBase bool

			add := func(address uint64) error {
				if address%word != 0 {
					return fmt.Errorf(
						"unaligned RELR relocation %#x",
						address,
					)
				}

				if _, ok := image.RegionAt(address); !ok {
					return fmt.Errorf(
						"RELR relocation targets unmapped address %#x",
						address,
					)
				}

				all = append(all, ELFRelocation{
					Section:       -1,
					Index:         len(all),
					TargetSection: -1,
					SymbolTable:   -1,
					Offset:        address,
					Encoding:      "RELR",
				})

				if len(all) > int(maxELFMetadataRecords) {
					return errors.New(
						"too many dynamic relocations",
					)
				}

				return nil
			}

			for i := uint64(0); i < relrSize; i += word {
				var value uint64

				if word == 4 {
					value = uint64(
						bo.Uint32(data[i : i+4]),
					)
				} else {
					value = bo.Uint64(
						data[i : i+8],
					)
				}

				if value&1 == 0 {
					if value > math.MaxUint64-word {
						return nil, errors.New(
							"RELR base overflow",
						)
					}

					if err := add(value); err != nil {
						return nil, err
					}

					base = value + word
					haveBase = true
					continue
				}

				if !haveBase {
					return nil, errors.New(
						"RELR bitmap without base",
					)
				}

				for bit := uint64(1); bit < word*8; bit++ {
					if value&(uint64(1)<<bit) == 0 {
						continue
					}

					delta := (bit - 1) * word

					if base > math.MaxUint64-delta {
						return nil, errors.New(
							"RELR address overflow",
						)
					}

					if err := add(base + delta); err != nil {
						return nil, err
					}
				}

				advance := (word*8 - 1) * word

				if base > math.MaxUint64-advance {
					return nil, errors.New(
						"RELR base overflow",
					)
				}

				base += advance
			}
		}
	}

	android, err := readAndroidRelocations(
		image,
		entries,
		bo,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"Android dynamic relocations: %w",
			err,
		)
	}

	all = append(all, android...)

	if len(all) > int(maxELFMetadataRecords) {
		return nil, fmt.Errorf(
			"combined dynamic relocation count exceeds limit",
		)
	}

	return all, nil
}
