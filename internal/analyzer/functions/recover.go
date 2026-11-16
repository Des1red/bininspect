package functions

import (
	"debug/elf"
	"fmt"
	"sort"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

// Function describes a recovered function candidate.
//
// For ET_REL, Entry is an offset within Section.
// For ET_EXEC/ET_DYN, Entry is an ELF virtual address.
type Function struct {
	Graph        int
	Section      int
	Entry        uint64
	Name         string
	Source       string
	Blocks       []int
	Instructions int
	Calls        []cfg.CallSite
}

type seed struct {
	name   string
	source string
}

func thumbBit(parsed *binary.ELFResult) uint64 {
	if parsed.Info.Architecture == binary.ArchARM {
		return 1
	}
	return 0
}

func symbols(parsed *binary.ELFResult) []binary.ELFSymbol {
	all := append(
		[]binary.ELFSymbol(nil),
		parsed.Metadata.Symbols...,
	)

	return append(all, parsed.DynamicMetadata.Symbols...)
}

// Leaders identifies candidate function entries before CFG
// construction. Keys refer to decoded.Sections slice positions.
func Leaders(
	parsed *binary.ELFResult,
	decoded decoder.Result,
) map[int]map[uint64]bool {
	result := make(map[int]map[uint64]bool)

	if parsed == nil {
		return result
	}

	starts := make([]map[uint64]bool, len(decoded.Sections))

	for i, section := range decoded.Sections {
		starts[i] = make(map[uint64]bool)

		for _, inst := range section.Instructions {
			starts[i][inst.Address] = true
		}
	}

	add := func(index int, address uint64) {
		if !starts[index][address] {
			return
		}

		if result[index] == nil {
			result[index] = make(map[uint64]bool)
		}

		result[index][address] = true
	}

	for i, section := range decoded.Sections {
		if parsed.Object == nil {
			add(i, parsed.Info.Entry&^thumbBit(parsed))
		}

		for _, inst := range section.Instructions {
			if inst.Flow != decoder.FlowCall ||
				!inst.HasTarget ||
				inst.Indirect ||
				len(inst.Relocations) != 0 {
				continue
			}

			add(i, inst.Target)
		}
	}

	for _, frame := range UnwindRanges(parsed) {
		for i := range decoded.Sections {
			add(i, frame.Start)
			add(i, frame.End)
		}
	}
	for _, sym := range symbols(parsed) {
		if sym.Type != elf.STT_FUNC ||
			sym.SectionIndex == uint32(elf.SHN_UNDEF) {
			continue
		}

		for i, section := range decoded.Sections {
			if parsed.Object != nil &&
				section.Index != int(sym.SectionIndex) {
				continue
			}

			add(i, sym.Value&^thumbBit(parsed))
		}
	}

	return result
}

// Recover discovers function candidates from ELF symbols,
// the entry point, and direct call targets.
//
// Reachability is calculated from CFG edges.
func Recover(
	parsed *binary.ELFResult,
	graphs []cfg.Graph,
) []Function {
	if parsed == nil {
		return nil
	}

	var result []Function
	unwind := UnwindRanges(parsed)

	for gi, graph := range graphs {
		byStart := make(map[uint64]int)

		for i, block := range graph.Blocks {
			byStart[block.Start] = i
		}

		if len(byStart) == 0 {
			continue
		}

		fdeEnds := frameBounds(graph, unwind)

		insideFrame := func(addr uint64) bool {
			for begin, end := range fdeEnds {
				if addr > begin && addr < end {
					return true
				}
			}
			return false
		}

		seeds := make(map[uint64]seed)

		priority := map[string]int{
			"symbol":          5,
			"entry":           4,
			"eh-frame":        3,
			"call":            2,
			"region-fallback": 1,
		}

		put := func(address uint64, name, source string) {
			if _, exists := byStart[address]; !exists {
				return
			}

			old, found := seeds[address]

			if !found || priority[source] > priority[old.source] {
				seeds[address] = seed{
					name:   name,
					source: source,
				}
			}
		}

		// Symbols are strong evidence of entry points.
		// Do not split an accepted FDE merely because another
		// function symbol points inside its recorded range.
		for _, sym := range symbols(parsed) {
			if sym.Type != elf.STT_FUNC ||
				sym.SectionIndex == uint32(elf.SHN_UNDEF) ||
				sym.Name == "" {
				continue
			}

			if parsed.Object != nil &&
				int(sym.SectionIndex) != graph.Section {
				continue
			}

			address := sym.Value &^ thumbBit(parsed)

			if insideFrame(address) {
				continue
			}

			put(address, sym.Name, "symbol")
		}

		if parsed.Object == nil &&
			parsed.Header.Type != elf.ET_REL {
			put(
				parsed.Info.Entry&^thumbBit(parsed),
				"_entry",
				"entry",
			)
		}

		// Accepted unwind ranges provide new entry candidates.
		for start := range fdeEnds {
			put(start, "", "eh-frame")
		}

		// Direct calls remain useful when unwind evidence
		// is absent. A call into an FDE's interior is not
		// automatically a separate function boundary.
		for _, call := range graph.Calls {
			if call.HasTarget &&
				!call.Indirect &&
				call.Symbol == "" &&
				!insideFrame(call.Target) {
				put(call.Target, "", "call")
			}
		}

		// No identifiable function entry: recover one
		// provisional function from the region's first block.
		if len(seeds) == 0 {
			put(
				graph.Blocks[0].Start,
				"",
				"region-fallback",
			)
		}

		entries := make([]uint64, 0, len(seeds))

		for addr := range seeds {
			entries = append(entries, addr)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i] < entries[j]
		})

		isSeed := make(map[int]bool)

		// Blocks entirely inside a validated unwind range
		// belong to that range's function candidate.
		fdeOwner := make(map[int]uint64)

		for start, end := range fdeEnds {
			for id, block := range graph.Blocks {
				if block.Start >= start && block.End <= end {
					fdeOwner[id] = start
				}
			}
		}

		for _, entry := range entries {
			isSeed[byStart[entry]] = true
		}

		adjacency := make([][]int, len(graph.Blocks))

		for _, edge := range graph.Edges {
			if edge.From < 0 ||
				edge.From >= len(adjacency) ||
				edge.To < 0 ||
				edge.To >= len(graph.Blocks) {
				continue
			}

			adjacency[edge.From] = append(
				adjacency[edge.From],
				edge.To,
			)
		}

		for _, entry := range entries {
			s := seeds[entry]

			// Retrieve the unwind range for this function.
			endBound, bounded := fdeEnds[entry]

			name := s.name
			if name == "" {
				name = fmt.Sprintf("sub_%x", entry)
			}

			fn := Function{
				Graph:   gi,
				Section: graph.Section,
				Entry:   entry,
				Name:    name,
				Source:  s.source,
			}

			seen := make(map[int]bool)
			queue := []int{byStart[entry]}

			for len(queue) > 0 {
				id := queue[0]
				queue = queue[1:]

				if seen[id] {
					continue
				}

				// Do not cross into another known
				// function's entry block.
				if isSeed[id] && id != byStart[entry] {
					continue
				}

				block := graph.Blocks[id]

				// A function with unwind boundaries cannot claim
				// blocks extending outside its recorded range.
				if bounded &&
					(block.Start < entry || block.End > endBound) {
					continue
				}

				// Do not let another function candidate claim
				// blocks inside an accepted FDE.
				if owner, protected := fdeOwner[id]; protected &&
					owner != entry {
					continue
				}

				seen[id] = true

				fn.Blocks = append(fn.Blocks, id)
				fn.Instructions +=
					len(graph.Blocks[id].Instructions)

				for _, dest := range adjacency[id] {
					if !seen[dest] {
						queue = append(queue, dest)
					}
				}
			}

			sort.Ints(fn.Blocks)

			for _, call := range graph.Calls {
				for _, id := range fn.Blocks {
					block := graph.Blocks[id]

					if call.Address >= block.Start &&
						call.Address < block.End {
						fn.Calls = append(
							fn.Calls, call,
						)
						break
					}
				}
			}

			result = append(result, fn)
		}
	}

	return result
}

func frameBounds(
	graph cfg.Graph,
	ranges []UnwindRange,
) map[uint64]uint64 {
	result := make(map[uint64]uint64)

	if len(graph.Blocks) == 0 {
		return result
	}

	byStart := make(map[uint64]bool, len(graph.Blocks))

	for _, block := range graph.Blocks {
		byStart[block.Start] = true
	}

	var valid []UnwindRange

	sectionEnd := graph.Blocks[len(graph.Blocks)-1].End

	for _, r := range ranges {
		if r.Start >= r.End ||
			!byStart[r.Start] ||
			r.End > sectionEnd {
			continue
		}

		valid = append(valid, r)
	}

	sort.Slice(valid, func(i, j int) bool {
		if valid[i].Start != valid[j].Start {
			return valid[i].Start < valid[j].Start
		}
		return valid[i].End < valid[j].End
	})

	// Overlapping FDEs are ambiguous and cannot
	// establish exclusive ownership.
	for i, r := range valid {
		if i > 0 && valid[i-1].End > r.Start {
			continue
		}

		if i+1 < len(valid) &&
			r.End > valid[i+1].Start {
			continue
		}

		result[r.Start] = r.End
	}

	return result
}
