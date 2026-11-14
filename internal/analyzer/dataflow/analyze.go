package dataflow

import (
	"debug/elf"
	"fmt"
	"sort"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/functions"
	"bininspect/internal/analyzer/resolve"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func symbolNames(
	parsed *binary.ELFResult,
) map[uint64]string {
	result := make(map[uint64]string)

	if parsed.Object != nil {
		// ET_REL addresses are section-relative,
		// not globally unique.
		return result
	}

	for _, sym := range parsed.Metadata.Symbols {
		if sym.Type == elf.STT_FUNC &&
			sym.Name != "" &&
			sym.SectionIndex != uint32(elf.SHN_UNDEF) {
			result[sym.Value] = sym.Name
		}
	}

	for _, sym := range parsed.DynamicMetadata.Symbols {
		if sym.Type == elf.STT_FUNC &&
			sym.Name != "" &&
			sym.SectionIndex != uint32(elf.SHN_UNDEF) {
			if result[sym.Value] == "" {
				result[sym.Value] = sym.Name
			}
		}
	}

	return result
}

func callTarget(
	inst decoder.Instruction,
	names map[uint64]string,
) string {
	for _, rel := range inst.Relocations {
		if rel.SymbolName != "" {
			return rel.SymbolName
		}
	}

	if inst.HasTarget && !inst.Indirect {
		if name := names[inst.Target]; name != "" {
			return name
		}
		return fmt.Sprintf("%#x", inst.Target)
	}

	return "unresolved"
}

// Analyze performs an intraprocedural, forward must-analysis.
// A known fact is preserved at a join only when all paths agree.
//
// The tracked domain is deliberately limited to constants,
// entry-SP-relative pointers, and known values in stack slots.
func Analyze(
	parsed *binary.ELFResult,
	graphs []cfg.Graph,
	funcs []functions.Function,
) Result {
	var out Result

	if parsed == nil {
		out.Warnings = append(
			out.Warnings,
			"missing ELF input",
		)
		return out
	}

	arch := parsed.Info.Architecture

	if arch != binary.ArchX86 &&
		arch != binary.ArchX8664 {
		out.Warnings = append(
			out.Warnings,
			"register, stack and argument tracking is not implemented for "+
				string(arch),
		)
		out.UntracedCalls = missingCallSites(
			graphs,
			nil,
			symbolNames(parsed),
		)
		return out
	}

	out.Supported = true

	word := int64(4)
	if arch == binary.ArchX8664 {
		word = 8
	}

	names := symbolNames(parsed)
	for address, name := range resolve.PLTTargets(parsed, graphs) {
		if names[address] == "" {
			names[address] = name
		}
	}

	for _, fn := range funcs {
		if fn.Graph < 0 || fn.Graph >= len(graphs) {
			out.Warnings = append(
				out.Warnings,
				fmt.Sprintf(
					"invalid CFG index for function %s",
					fn.Name,
				),
			)
			continue
		}

		graph := graphs[fn.Graph]

		member := make(map[int]bool, len(fn.Blocks))
		start := -1

		for _, id := range fn.Blocks {
			if id < 0 || id >= len(graph.Blocks) {
				continue
			}

			member[id] = true

			if graph.Blocks[id].Start == fn.Entry {
				start = id
			}
		}

		if start < 0 {
			out.Warnings = append(
				out.Warnings,
				fmt.Sprintf(
					"entry block missing for function %s",
					fn.Name,
				),
			)
			continue
		}

		// Precompute successors instead of repeatedly
		// scanning every CFG edge.
		succ := make([][]int, len(graph.Blocks))

		for _, edge := range graph.Edges {
			if edge.From >= 0 &&
				edge.From < len(succ) &&
				member[edge.To] {
				succ[edge.From] = append(
					succ[edge.From],
					edge.To,
				)
			}
		}

		incoming := map[int]state{
			start: newState(),
		}

		queue := []int{start}
		queued := map[int]bool{
			start: true,
		}

		steps := 0
		limit := len(member)*64 + 256

		for len(queue) > 0 && steps < limit {
			id := queue[0]
			queue = queue[1:]

			queued[id] = false
			steps++

			st := incoming[id].clone()

			for _, inst := range graph.Blocks[id].Instructions {
				if inst.Flow == decoder.FlowCall {
					st.clobber(arch)
				} else {
					st.step(inst, arch, word)
				}
			}

			for _, to := range succ[id] {
				old, exists := incoming[to]

				if !exists {
					incoming[to] = st.clone()
				} else {
					if !old.intersect(st) {
						continue
					}
					incoming[to] = old
				}

				if !queued[to] {
					queue = append(queue, to)
					queued[to] = true
				}
			}
		}

		if len(queue) > 0 {
			out.Warnings = append(
				out.Warnings,
				fmt.Sprintf(
					"data-flow iteration limit reached in %s; results omitted",
					fn.Name,
				),
			)
			continue
		}

		stackUse := StackUse{
			Function: fn.Name,
			Section:  graph.Section,
			Entry:    fn.Entry,
		}

		observeStack := func(st state) {
			v := st.regs["rsp"]

			if v.Kind != "stack-address" {
				stackUse.Partial = true
			} else if v.StackOffset < 0 &&
				-v.StackOffset > stackUse.MaxDepthBytes {
				stackUse.MaxDepthBytes = -v.StackOffset
			}
		}

		// Final pass: emit evidence exactly once using
		// converged block-entry states.
		for _, id := range fn.Blocks {
			entry, ok := incoming[id]

			if !ok || !member[id] {
				continue
			}

			st := entry.clone()
			observeStack(st)

			for _, inst := range graph.Blocks[id].Instructions {
				if inst.Flow == decoder.FlowCall {
					out.Calls = append(
						out.Calls,
						CallTrace{
							Function: fn.Name,
							Section:  graph.Section,
							Address:  inst.Address,
							Target: callTarget(
								inst, names,
							),
							Indirect: inst.Indirect,
							Arguments: arguments(
								st, arch,
							),
						},
					)

					st.clobber(arch)
				} else {
					st.step(inst, arch, word)
				}

				observeStack(st)
			}
		}

		out.Stack = append(out.Stack, stackUse)
	}

	out.Calls = mergeCallSites(out.Calls)
	out.UntracedCalls = missingCallSites(
		graphs,
		out.Calls,
		names,
	)
	sort.Slice(out.Calls, func(i, j int) bool {
		if out.Calls[i].Section != out.Calls[j].Section {
			return out.Calls[i].Section < out.Calls[j].Section
		}

		if out.Calls[i].Address != out.Calls[j].Address {
			return out.Calls[i].Address < out.Calls[j].Address
		}

		return out.Calls[i].Function < out.Calls[j].Function
	})

	return out
}
