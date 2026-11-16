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

func x64RegisterFamily(name string) string {
	switch name {
	case "RAX", "EAX", "AX", "AL", "AH":
		return "RAX"
	case "RBX", "EBX", "BX", "BL", "BH":
		return "RBX"
	case "RCX", "ECX", "CX", "CL", "CH":
		return "RCX"
	case "RDX", "EDX", "DX", "DL", "DH":
		return "RDX"
	case "RDI", "EDI", "DI", "DIL":
		return "RDI"
	case "RSI", "ESI", "SI", "SIL":
		return "RSI"
	case "RBP", "EBP", "BP", "BPL":
		return "RBP"
	case "RSP", "ESP", "SP", "SPL":
		return "RSP"
	case "R8", "R8D", "R8W", "R8B":
		return "R8"
	case "R9", "R9D", "R9W", "R9B":
		return "R9"
	case "R10", "R10D", "R10W", "R10B":
		return "R10"
	case "R11", "R11D", "R11W", "R11B":
		return "R11"
	case "R12", "R12D", "R12W", "R12B":
		return "R12"
	case "R13", "R13D", "R13W", "R13B":
		return "R13"
	case "R14", "R14D", "R14W", "R14B":
		return "R14"
	case "R15", "R15D", "R15W", "R15B":
		return "R15"
	}
	return name
}

func changesRegister(
	inst decoder.Instruction,
	fullName string,
) bool {
	if len(inst.Operands) == 0 ||
		inst.Operands[0].Kind != decoder.OperandRegister {
		return false
	}

	switch inst.Mnemonic {
	case "CMP", "TEST", "PUSH", "NOP":
		return false
	}

	return x64RegisterFamily(
		inst.Operands[0].Register,
	) == fullName
}

func ripMemoryAddress(
	inst decoder.Instruction,
	operand decoder.Operand,
) (uint64, bool) {
	if operand.Kind != decoder.OperandMemory ||
		operand.Memory.Base != "RIP" ||
		operand.Memory.Index != "" {
		return 0, false
	}

	if inst.Address > math.MaxUint64-uint64(inst.Size) {
		return 0, false
	}

	return relativeAddress(
		inst.Address+uint64(inst.Size),
		operand.Memory.Displacement,
	)
}

// Check whether the value compared by CMP is also the
// index used by the jump-table MOVSXD.
//
// Supported:
//  1. CMP EAX / RBX / ... followed by the same index.
//  2. CMP CL followed by MOVZX EDX, CL.
//  3. CMP [RIP+disp] followed by MOV EAX from that
//     same RIP-relative memory address.
//
// Cases with unsupported register transformations
// remain unresolved.
func indexMatchesGuard(
	cmp decoder.Instruction,
	middle []decoder.Instruction,
	indexRegister string,
) bool {
	if len(cmp.Operands) != 2 {
		return false
	}

	compared := cmp.Operands[0]
	lastWrite := -1

	for i, inst := range middle {
		if changesRegister(inst, indexRegister) {
			lastWrite = i
		}
	}

	if compared.Kind == decoder.OperandRegister {
		// Direct comparison of the index register.
		if lastWrite == -1 &&
			x64RegisterFamily(compared.Register) ==
				indexRegister {
			return true
		}

		if lastWrite < 0 {
			return false
		}

		// A zero-extended copy from a compared byte
		// register, e.g. CMP CL followed by
		// MOVZX EDX, CL.
		inst := middle[lastWrite]

		if inst.Mnemonic != "MOVZX" ||
			len(inst.Operands) != 2 ||
			inst.Operands[1].Kind !=
				decoder.OperandRegister ||
			inst.Operands[1].Register !=
				compared.Register {
			return false
		}

		guardedFamily := x64RegisterFamily(
			compared.Register,
		)

		for _, prior := range middle[:lastWrite] {
			if changesRegister(prior, guardedFamily) {
				return false
			}
		}

		return true
	}

	if compared.Kind == decoder.OperandMemory {
		if lastWrite < 0 {
			return false
		}

		// A checked RIP-relative global subsequently
		// loaded into the index register.
		inst := middle[lastWrite]

		if inst.Mnemonic != "MOV" ||
			len(inst.Operands) != 2 ||
			inst.Operands[1].Kind !=
				decoder.OperandMemory {
			return false
		}

		before, okBefore := ripMemoryAddress(
			cmp, compared,
		)

		after, okAfter := ripMemoryAddress(
			inst, inst.Operands[1],
		)

		if !okBefore ||
			!okAfter ||
			before != after ||
			compared.Memory.SizeBytes != 4 ||
			inst.Operands[1].Memory.SizeBytes != 4 {
			return false
		}

		// Reject explicit RIP-relative writes to the
		// compared location between CMP and reload.
		for _, prior := range middle[:lastWrite] {
			if len(prior.Operands) == 0 ||
				prior.Operands[0].Kind !=
					decoder.OperandMemory {
				continue
			}

			address, ok := ripMemoryAddress(
				prior,
				prior.Operands[0],
			)

			if ok && address == before {
				return false
			}
		}

		return true
	}

	return false
}

// Find a nearby CMP + unsigned JA guard.
//
// Ordinary instructions, including an intervening LEA
// and MOVZX, are allowed between JA and MOVSXD.
// Any intervening control transfer is rejected.
func guardedTableCount(
	insts []decoder.Instruction,
	loadIndex int,
	indexRegister string,
) (uint64, uint64, bool) {
	if loadIndex <= 1 {
		return 0, 0, false
	}

	load := insts[loadIndex]

	for g := loadIndex - 1; g >= 1; g-- {
		instruction := insts[g]

		if load.Address < instruction.Address ||
			load.Address-instruction.Address > 128 {
			break
		}

		if !adjacent(instruction, insts[g+1]) {
			break
		}

		if instruction.Flow == decoder.FlowNone {
			continue
		}

		if instruction.Mnemonic != "JA" ||
			!instruction.HasTarget ||
			instruction.Indirect {
			break
		}

		cmp := insts[g-1]

		if !adjacent(cmp, instruction) ||
			cmp.Mnemonic != "CMP" ||
			len(cmp.Operands) != 2 ||
			cmp.Operands[1].Kind !=
				decoder.OperandImmediate {
			break
		}

		upper := cmp.Operands[1].Immediate

		if upper < 0 ||
			upper > 4095 ||
			!indexMatchesGuard(
				cmp,
				insts[g+1:loadIndex],
				indexRegister,
			) {
			break
		}

		return cmp.Address, uint64(upper) + 1, true
	}

	return 0, 0, false
}

// JumpTables recognizes guarded x86-64 relative-offset
// dispatches:
//
//	CMP checked-index, maximum
//	JA  out-of-range
//	[optional instructions]
//	MOVSXD destination, DWORD [base+index*4]
//	ADD destination, base
//	JMP destination
//
// The base must originate from a dominating
// RIP-relative LEA. Every table target must resolve
// to a decoded instruction start inside one FDE.
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

		for i := 2; i < len(insts); i++ {
			load := insts[i-2]
			add := insts[i-1]
			jump := insts[i]

			if !adjacent(load, add) ||
				!adjacent(add, jump) ||
				load.Mnemonic != "MOVSXD" ||
				len(load.Operands) != 2 ||
				load.Operands[0].Kind !=
					decoder.OperandRegister ||
				load.Operands[1].Kind !=
					decoder.OperandMemory {
				continue
			}

			mem := load.Operands[1].Memory
			destination := load.Operands[0].Register

			if mem.Base == "" ||
				mem.Index == "" ||
				mem.Base == "RIP" ||
				mem.Base == destination ||
				mem.Scale != 4 ||
				mem.SizeBytes != 4 ||
				mem.Displacement != 0 {
				continue
			}

			if add.Mnemonic != "ADD" ||
				len(add.Operands) != 2 ||
				!register(add.Operands[0], destination) ||
				!register(add.Operands[1], mem.Base) {
				continue
			}

			if jump.Mnemonic != "JMP" ||
				!jump.Indirect ||
				len(jump.Operands) != 1 ||
				!register(jump.Operands[0], destination) {
				continue
			}

			guardAddress, entryCount, ok :=
				guardedTableCount(
					insts,
					i-2,
					x64RegisterFamily(mem.Index),
				)

			if !ok {
				continue
			}

			// The guard and dispatch must fall inside
			// the same unwind range.
			var frame *functions.UnwindRange

			for fi := range frames {
				r := &frames[fi]

				if guardAddress >= r.Start &&
					jump.Address < r.End {
					frame = r
					break
				}
			}

			if frame == nil {
				continue
			}

			// The initial CFG must establish that the
			// bounds check dominates this dispatch.
			if !dominatesDispatch(
				*graph,
				frame.Start,
				guardAddress,
				jump.Address,
			) {
				continue
			}

			// Find the RIP-relative LEA that establishes
			// the table base register.
			leaIndex := -1

			for p := i - 3; p >= 0; p-- {
				candidate := insts[p]

				if candidate.Address < frame.Start ||
					load.Address < candidate.Address ||
					load.Address-candidate.Address > 4096 {
					break
				}

				if candidate.Mnemonic == "LEA" &&
					len(candidate.Operands) == 2 &&
					register(
						candidate.Operands[0],
						mem.Base,
					) &&
					candidate.Operands[1].Kind ==
						decoder.OperandMemory &&
					candidate.Operands[1].Memory.Base ==
						"RIP" &&
					candidate.Operands[1].Memory.Index ==
						"" {
					leaIndex = p
					break
				}
			}

			if leaIndex < 0 {
				continue
			}

			lea := insts[leaIndex]

			// Reject a possible overwrite of the
			// base register before table lookup.
			safe := true

			for p := leaIndex + 1; p < i-2; p++ {
				if changesRegister(
					insts[p],
					mem.Base,
				) {
					safe = false
					break
				}
			}

			if !safe ||
				!dominatesDispatch(
					*graph,
					frame.Start,
					lea.Address,
					jump.Address,
				) {
				continue
			}

			base, ok := ripMemoryAddress(
				lea,
				lea.Operands[1],
			)

			if !ok {
				continue
			}

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
