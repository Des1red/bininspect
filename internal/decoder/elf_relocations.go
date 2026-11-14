package decoder

import (
	"sort"

	"bininspect/internal/binary"
)

func attachRelocations(
	section *DecodedSection,
	parsed *binary.ELFResult,
	object bool,
) {
	if len(section.Instructions) == 0 {
		return
	}

	relocations := append(
		[]binary.ELFRelocation(nil),
		parsed.Metadata.Relocations...,
	)

	if !object {
		relocations = append(
			relocations,
			parsed.DynamicMetadata.Relocations...,
		)
	}

	sort.Slice(
		section.Instructions,
		func(i, j int) bool {
			return section.Instructions[i].Address <
				section.Instructions[j].Address
		},
	)

	type key struct {
		offset   uint64
		typ      uint32
		symbol   uint32
		encoding string
	}

	seen := make(map[key]bool)

	for _, rel := range relocations {
		if object &&
			rel.TargetSection != section.Index {
			continue
		}

		k := key{
			rel.Offset,
			rel.Type,
			rel.SymbolIndex,
			rel.Encoding,
		}

		if seen[k] {
			continue
		}

		seen[k] = true

		i := sort.Search(
			len(section.Instructions),
			func(i int) bool {
				return section.Instructions[i].Address >
					rel.Offset
			},
		) - 1

		if i < 0 {
			continue
		}

		inst := &section.Instructions[i]

		if rel.Offset-inst.Address >=
			uint64(inst.Size) {
			continue
		}

		inst.Relocations = append(
			inst.Relocations,
			RelocationReference{
				Section:     rel.Section,
				Offset:      rel.Offset,
				WithinInsn:  uint8(rel.Offset - inst.Address),
				Type:        rel.Type,
				SymbolIndex: rel.SymbolIndex,
				SymbolName:  rel.SymbolName,
				Addend:      rel.Addend,
				HasAddend:   rel.HasAddend,
				Encoding:    rel.Encoding,
			},
		)
	}
}
