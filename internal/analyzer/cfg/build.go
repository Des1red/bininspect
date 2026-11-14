package cfg

import (
	"fmt"
	"math"
	"sort"

	"bininspect/internal/decoder"
)

func Build(decoded decoder.Result) ([]Graph, error) {
	return BuildWithLeaders(decoded, nil)
}

func BuildWithLeaders(
	decoded decoder.Result,
	extra map[int]map[uint64]bool,
) ([]Graph, error) {
	graphs := make([]Graph, 0, len(decoded.Sections))

	for i, section := range decoded.Sections {
		graph, err := buildSection(section, extra[i])
		if err != nil {
			return nil, fmt.Errorf(
				"CFG section %d (%s): %w",
				section.Index, section.Name, err,
			)
		}

		graphs = append(graphs, graph)
	}

	return graphs, nil
}

func buildSection(
	section decoder.DecodedSection,
	extra map[uint64]bool,
) (Graph, error) {
	graph := Graph{
		Section: section.Index,
		Name:    section.Name,
	}

	insts := append(
		[]decoder.Instruction(nil),
		section.Instructions...,
	)
	if len(insts) == 0 {
		return graph, nil
	}

	sort.Slice(insts, func(i, j int) bool {
		return insts[i].Address < insts[j].Address
	})

	starts := make(map[uint64]struct{}, len(insts))

	for i, inst := range insts {
		if inst.Size == 0 ||
			inst.Address > math.MaxUint64-uint64(inst.Size) {
			return Graph{}, fmt.Errorf(
				"invalid instruction span at %#x",
				inst.Address,
			)
		}

		if i > 0 &&
			insts[i-1].Address+
				uint64(insts[i-1].Size) > inst.Address {
			return Graph{}, fmt.Errorf(
				"overlapping instructions at %#x",
				inst.Address,
			)
		}

		starts[inst.Address] = struct{}{}
	}

	leaders := map[uint64]bool{
		insts[0].Address: true,
	}
	for address := range extra {
		if _, ok := starts[address]; ok {
			leaders[address] = true
		}
	}
	for i, inst := range insts {
		// Never create fallthrough across undecoded bytes.
		if i > 0 &&
			insts[i-1].Address+
				uint64(insts[i-1].Size) != inst.Address {
			leaders[inst.Address] = true
		}

		if inst.Flow == decoder.FlowJump ||
			inst.Flow == decoder.FlowConditional {
			if inst.HasTarget &&
				!inst.Indirect &&
				len(inst.Relocations) == 0 {
				if _, ok := starts[inst.Target]; ok {
					leaders[inst.Target] = true
				}
			}
		}

		if isTerminator(inst.Flow) && i+1 < len(insts) {
			leaders[insts[i+1].Address] = true
		}
	}

	for i, inst := range insts {
		if i == 0 || leaders[inst.Address] {
			graph.Blocks = append(
				graph.Blocks,
				Block{Start: inst.Address},
			)
		}

		block := &graph.Blocks[len(graph.Blocks)-1]
		block.Instructions = append(
			block.Instructions, inst,
		)
		block.End = inst.Address + uint64(inst.Size)
	}

	byStart := make(map[uint64]int, len(graph.Blocks))

	for i, block := range graph.Blocks {
		byStart[block.Start] = i
	}

	addDirect := func(
		from int,
		kind EdgeKind,
		inst decoder.Instruction,
	) {
		edge := Edge{
			From:   from,
			To:     -1,
			Kind:   kind,
			Symbol: relocationSymbol(inst),
		}

		if inst.Indirect {
			edge.Kind = EdgeIndirect
		} else if inst.HasTarget {
			edge.Target = inst.Target

			// A relocation means the encoded target
			// may not be the final linked destination.
			if len(inst.Relocations) == 0 {
				if to, ok := byStart[inst.Target]; ok {
					edge.To = to
				}
			}
		}

		graph.Edges = append(graph.Edges, edge)
	}

	for i, block := range graph.Blocks {
		last := block.Instructions[len(block.Instructions)-1]

		addFallthrough := func(kind EdgeKind) {
			if i+1 < len(graph.Blocks) &&
				graph.Blocks[i+1].Start == block.End {
				graph.Edges = append(
					graph.Edges,
					Edge{
						From:   i,
						To:     i + 1,
						Target: block.End,
						Kind:   kind,
					},
				)
			}
		}

		switch last.Flow {
		case decoder.FlowJump:
			addDirect(i, EdgeBranch, last)

		case decoder.FlowConditional:
			addDirect(i, EdgeConditional, last)
			addFallthrough(EdgeConditionalFalse)

		case decoder.FlowCall:
			graph.Calls = append(
				graph.Calls,
				CallSite{
					Address: last.Address,
					Target:  last.Target,
					HasTarget: last.HasTarget &&
						len(last.Relocations) == 0,
					Indirect: last.Indirect,
					Symbol:   relocationSymbol(last),
				},
			)
			addFallthrough(EdgeFallthrough)

		case decoder.FlowReturn, decoder.FlowTrap:
			// No automatic successor.

		default:
			addFallthrough(EdgeFallthrough)
		}
	}

	return graph, nil
}

func isTerminator(flow decoder.FlowKind) bool {
	switch flow {
	case decoder.FlowJump,
		decoder.FlowConditional,
		decoder.FlowCall,
		decoder.FlowReturn,
		decoder.FlowTrap:
		return true
	default:
		return false
	}
}

func relocationSymbol(inst decoder.Instruction) string {
	for _, ref := range inst.Relocations {
		if ref.SymbolName != "" {
			return ref.SymbolName
		}
	}

	return ""
}
