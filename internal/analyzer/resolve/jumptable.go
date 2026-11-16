package resolve

import (
	"debug/elf"
	stdbin "encoding/binary"
	"math"
	"sort"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/functions"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

type JumpTable struct {
	Section  int
	Dispatch uint64
	Base     uint64
	Targets  []uint64
}

func register(op decoder.Operand, name string) bool {
	return op.Kind == decoder.OperandRegister &&
		op.Register == name
}

func adjacent(a, b decoder.Instruction) bool {
	return a.Address+uint64(a.Size) == b.Address
}

func relativeAddress(base uint64, delta int64) (uint64, bool) {
	// Normalize zero-extended x86 disp32 values.
	if delta >= 1<<31 && delta <= (1<<32)-1 {
		delta = int64(int32(uint32(delta)))
	}

	if delta >= 0 {
		if uint64(delta) > math.MaxUint64-base {
			return 0, false
		}
		return base + uint64(delta), true
	}

	if delta == math.MinInt64 {
		return 0, false
	}

	amount := uint64(-delta)
	if amount > base {
		return 0, false
	}

	return base - amount, true
}

// Decode a complete table of signed 32-bit offsets.
// All entries must point to instruction starts inside
// the same accepted unwind range.
func relativeTableTargets(
	raw []byte,
	base, start, end uint64,
	instructionStarts map[uint64]bool,
) ([]uint64, bool) {
	if len(raw) == 0 || len(raw)%4 != 0 {
		return nil, false
	}

	unique := make(map[uint64]bool)

	for i := 0; i < len(raw); i += 4 {
		offset := int64(int32(
			stdbin.LittleEndian.Uint32(raw[i:]),
		))

		target, ok := relativeAddress(base, offset)
		if !ok ||
			target < start ||
			target >= end ||
			!instructionStarts[target] {
			return nil, false
		}

		unique[target] = true
	}

	targets := make([]uint64, 0, len(unique))
	for target := range unique {
		targets = append(targets, target)
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i] < targets[j]
	})

	return targets, true
}

func containingBlock(graph cfg.Graph, address uint64) int {
	for i, block := range graph.Blocks {
		if address >= block.Start &&
			address < block.End {
			return i
		}
	}
	return -1
}

func reachableWithout(
	graph cfg.Graph,
	start, destination, excluded int,
) bool {
	if start < 0 || destination < 0 ||
		start == excluded {
		return false
	}

	adjacency := make([][]int, len(graph.Blocks))

	for _, edge := range graph.Edges {
		if edge.From >= 0 &&
			edge.From < len(adjacency) &&
			edge.To >= 0 &&
			edge.To < len(adjacency) {
			adjacency[edge.From] = append(
				adjacency[edge.From], edge.To,
			)
		}
	}

	queue := []int{start}
	seen := make(map[int]bool)

	for len(queue) != 0 {
		id := queue[0]
		queue = queue[1:]

		if seen[id] || id == excluded {
			continue
		}
		if id == destination {
			return true
		}

		seen[id] = true
		queue = append(queue, adjacency[id]...)
	}

	return false
}

// A RIP-relative LEA is accepted only when its block
// dominates the dispatch block on resolved CFG paths.
func dominatesDispatch(
	graph cfg.Graph,
	entry, lea, dispatch uint64,
) bool {
	root := containingBlock(graph, entry)
	producer := containingBlock(graph, lea)
	consumer := containingBlock(graph, dispatch)

	if root < 0 || producer < 0 || consumer < 0 {
		return false
	}

	if producer == consumer && lea > dispatch {
		return false
	}

	return reachableWithout(
		graph, root, consumer, -1,
	) && !reachableWithout(
		graph, root, consumer, producer,
	)
}

func writesTableBase(inst decoder.Instruction) bool {
	if len(inst.Operands) == 0 {
		return false
	}

	// Conservative rejection: even read-only instructions
	// with RBX as the first operand may be rejected.
	first := inst.Operands[0]

	for _, name := range []string{
		"RBX", "EBX", "BX", "BL", "BH",
	} {
		if register(first, name) {
			return true
		}
	}

	return false
}

// JumpTables recognizes the guarded x86-64 pattern:
//
//	CMP EAX, max
//	JA outside
//	MOVSXD RAX, DWORD [RBX + RAX*4]
//	ADD RAX, RBX
//	JMP RAX
//
// RBX must come from a dominating RIP-relative LEA.
// Unsupported or ambiguous cases stay unresolved.
func JumpTables(
	parsed *binary.ELFResult,
	decoded decoder.Result,
	graphs []cfg.Graph,
) []JumpTable {
	if parsed == nil ||
		parsed.Image == nil ||
		parsed.Info.Architecture != binary.ArchX8664 ||
		parsed.Header.Type == elf.ET_REL {
		return nil
	}

	frames := functions.UnwindRanges(parsed)
	var tables []JumpTable

	for _, section := range decoded.Sections {
		var graph *cfg.Graph

		for gi := range graphs {
			if graphs[gi].Section == section.Index {
				graph = &graphs[gi]
				break
			}
		}

		if graph == nil {
			continue
		}

		insts := section.Instructions
		starts := make(map[uint64]bool, len(insts))

		for _, inst := range insts {
			starts[inst.Address] = true
		}

		for i := 4; i < len(insts); i++ {
			cmp := insts[i-4]
			guard := insts[i-3]
			load := insts[i-2]
			add := insts[i-1]
			jump := insts[i]

			if !adjacent(cmp, guard) ||
				!adjacent(guard, load) ||
				!adjacent(load, add) ||
				!adjacent(add, jump) {
				continue
			}

			if cmp.Mnemonic != "CMP" ||
				len(cmp.Operands) != 2 ||
				!register(cmp.Operands[0], "EAX") ||
				cmp.Operands[1].Kind != decoder.OperandImmediate {
				continue
			}

			maxIndex := cmp.Operands[1].Immediate

			if maxIndex < 0 || maxIndex > 4095 {
				continue
			}

			if guard.Mnemonic != "JA" ||
				len(guard.Operands) != 1 ||
				!guard.Operands[0].HasTarget {
				continue
			}

			if load.Mnemonic != "MOVSXD" ||
				len(load.Operands) != 2 ||
				!register(load.Operands[0], "RAX") ||
				load.Operands[1].Kind != decoder.OperandMemory {
				continue
			}

			mem := load.Operands[1].Memory

			if mem.Base != "RBX" ||
				mem.Index != "RAX" ||
				mem.Scale != 4 ||
				mem.SizeBytes != 4 ||
				mem.Displacement != 0 {
				continue
			}

			if add.Mnemonic != "ADD" ||
				len(add.Operands) != 2 ||
				!register(add.Operands[0], "RAX") ||
				!register(add.Operands[1], "RBX") {
				continue
			}

			if jump.Mnemonic != "JMP" ||
				!jump.Indirect ||
				len(jump.Operands) != 1 ||
				!register(jump.Operands[0], "RAX") {
				continue
			}

			// Require an accepted unwind range containing
			// the entire dispatch sequence.
			var frame *functions.UnwindRange

			for fi := range frames {
				r := &frames[fi]

				if cmp.Address >= r.Start &&
					jump.Address < r.End {
					frame = r
					break
				}
			}

			if frame == nil {
				continue
			}

			// Locate the nearest RIP-relative LEA RBX
			// inside this function, with a bounded search.
			leaIndex := -1

			for p := i - 5; p >= 0; p-- {
				candidate := insts[p]

				if candidate.Address < frame.Start ||
					jump.Address-candidate.Address > 4096 {
					break
				}

				if candidate.Mnemonic != "LEA" ||
					len(candidate.Operands) != 2 ||
					!register(candidate.Operands[0], "RBX") ||
					candidate.Operands[1].Kind !=
						decoder.OperandMemory ||
					candidate.Operands[1].Memory.Base != "RIP" ||
					candidate.Operands[1].Memory.Index != "" {
					continue
				}

				leaIndex = p
				break
			}

			if leaIndex < 0 {
				continue
			}

			lea := insts[leaIndex]

			// Reject if the linear instruction span
			// contains another possible RBX write.
			safe := true

			for p := leaIndex + 1; p < i; p++ {
				if writesTableBase(insts[p]) {
					safe = false
					break
				}
			}

			if !safe || !dominatesDispatch(
				*graph,
				frame.Start,
				lea.Address,
				jump.Address,
			) {
				continue
			}

			base, ok := relativeAddress(
				lea.Address+uint64(lea.Size),
				lea.Operands[1].Memory.Displacement,
			)
			if !ok {
				continue
			}

			entryCount := uint64(maxIndex) + 1

			raw, err := parsed.Image.ReadVirtual(
				base,
				entryCount*4,
			)
			if err != nil {
				continue
			}

			targets, ok := relativeTableTargets(
				raw,
				base,
				frame.Start,
				frame.End,
				starts,
			)

			if !ok {
				continue
			}

			tables = append(tables, JumpTable{
				Section:  section.Index,
				Dispatch: jump.Address,
				Base:     base,
				Targets:  targets,
			})
		}
	}

	return tables
}

// Mark jump-table destinations as block leaders before
// the final CFG is built.
func AddJumpTableLeaders(
	leaders map[int]map[uint64]bool,
	decoded decoder.Result,
	tables []JumpTable,
) {
	for i, section := range decoded.Sections {
		for _, table := range tables {
			if table.Section != section.Index {
				continue
			}

			if leaders[i] == nil {
				leaders[i] = make(map[uint64]bool)
			}

			for _, target := range table.Targets {
				leaders[i][target] = true
			}
		}
	}
}

// Attach recovered destinations to the final CFG.
// Leave unrelated indirect branches untouched.
func AddJumpTableEdges(
	graphs []cfg.Graph,
	tables []JumpTable,
) {
	for gi := range graphs {
		graph := &graphs[gi]

		byStart := make(map[uint64]int)

		for id, block := range graph.Blocks {
			byStart[block.Start] = id
		}

		for _, table := range tables {
			if table.Section != graph.Section {
				continue
			}

			source := containingBlock(*graph, table.Dispatch)
			if source < 0 {
				continue
			}

			block := graph.Blocks[source]

			if len(block.Instructions) == 0 {
				continue
			}

			last := block.Instructions[len(block.Instructions)-1]

			if last.Address != table.Dispatch ||
				last.Flow != decoder.FlowJump ||
				!last.Indirect {
				continue
			}

			// All destinations must correspond to actual
			// basic-block starts in the rebuilt CFG.
			destinations := make([]int, 0, len(table.Targets))
			valid := true

			for _, target := range table.Targets {
				id, ok := byStart[target]
				if !ok {
					valid = false
					break
				}

				destinations = append(destinations, id)
			}

			if !valid {
				continue
			}

			// The bounded table is complete: replace its
			// unresolved sentinel with concrete successors.
			edges := graph.Edges[:0]

			for _, edge := range graph.Edges {
				if edge.From == source &&
					edge.To == -1 &&
					edge.Kind == cfg.EdgeIndirect {
					continue
				}

				edges = append(edges, edge)
			}

			graph.Edges = edges

			for _, destination := range destinations {
				exists := false

				for _, edge := range graph.Edges {
					if edge.From == source &&
						edge.To == destination {
						exists = true
						break
					}
				}

				if !exists {
					graph.Edges = append(
						graph.Edges,
						cfg.Edge{
							From: source,
							To:   destination,
							Kind: cfg.EdgeIndirect,
						},
					)
				}
			}
		}
	}
}
