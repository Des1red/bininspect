package analyzer_test

import (
	"os"
	"sort"
	"testing"

	"bininspect/internal/analyzer/functions"
	"bininspect/internal/binary"
	"bininspect/internal/collect"
)

func TestProbeRemainingFDECoverage(t *testing.T) {
	const target = "/bin/ls"

	result, err := collect.Engine(target)
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := binary.Engine(file, uint64(info.Size()))
	if err != nil {
		t.Fatal(err)
	}

	frames := functions.UnwindRanges(parsed)

	type group struct {
		start      uint64
		end        uint64
		calls      []uint64
		recovered  bool
		unresolved int
	}

	groups := make(map[uint64]*group)
	var outside []uint64

	for _, call := range result.DataFlow.UntracedCalls {
		found := false

		for _, frame := range frames {
			if call.Address < frame.Start ||
				call.Address >= frame.End {
				continue
			}

			g := groups[frame.Start]
			if g == nil {
				g = &group{
					start: frame.Start,
					end:   frame.End,
				}
				groups[frame.Start] = g
			}

			g.calls = append(g.calls, call.Address)
			found = true
			break
		}

		if !found {
			outside = append(outside, call.Address)
		}
	}

	for _, fn := range result.Functions {
		if g := groups[fn.Entry]; g != nil {
			g.recovered = true
		}
	}

	// Count unresolved outgoing edges from recovered blocks
	// inside each FDE that still contains untraced calls.
	for gi, graph := range result.Graphs {
		owned := make(map[int]bool)

		for _, fn := range result.Functions {
			if fn.Graph != gi {
				continue
			}

			for _, id := range fn.Blocks {
				owned[id] = true
			}
		}

		for _, edge := range graph.Edges {
			if edge.To != -1 ||
				edge.From < 0 ||
				edge.From >= len(graph.Blocks) ||
				!owned[edge.From] {
				continue
			}

			address := graph.Blocks[edge.From].Start

			for _, g := range groups {
				if address >= g.start &&
					address < g.end {
					g.unresolved++

					block := graph.Blocks[edge.From]

					if len(block.Instructions) == 0 {
						break
					}

					last := block.Instructions[len(block.Instructions)-1]

					t.Logf(
						"UNRESOLVED: FDE=[%#x,%#x) "+
							"block=%#x kind=%s "+
							"address=%#x mnemonic=%s "+
							"indirect=%t target=%#x",
						g.start,
						g.end,
						block.Start,
						edge.Kind,
						last.Address,
						last.Mnemonic,
						last.Indirect,
						last.Target,
					)

					// Inspect instructions immediately before the
					// unresolved transfer.
					windowStart := uint64(0)
					if last.Address > 128 {
						windowStart = last.Address - 128
					}

					for _, earlier := range graph.Blocks {
						if earlier.End <= windowStart ||
							earlier.Start > last.Address {
							continue
						}

						for _, inst := range earlier.Instructions {
							if inst.Address < windowStart ||
								inst.Address > last.Address {
								continue
							}

							t.Logf(
								"  %#x: %-10s "+
									"operands=%+v bytes=% x",
								inst.Address,
								inst.Mnemonic,
								inst.Operands,
								inst.Bytes,
							)
						}
					}

					// Also identify the resolved CFG predecessors.
					for _, incoming := range graph.Edges {
						if incoming.To != edge.From ||
							incoming.From < 0 ||
							incoming.From >= len(graph.Blocks) {
							continue
						}

						predecessor := graph.Blocks[incoming.From]

						t.Logf(
							"  PREDECESSOR: %#x edge=%s",
							predecessor.Start,
							incoming.Kind,
						)
					}

					break
				}
			}
		}
	}

	ordered := make([]*group, 0, len(groups))
	insideCount := 0

	for _, g := range groups {
		ordered = append(ordered, g)
		insideCount += len(g.calls)
	}

	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i].calls) != len(ordered[j].calls) {
			return len(ordered[i].calls) > len(ordered[j].calls)
		}
		return ordered[i].start < ordered[j].start
	})

	for _, g := range ordered {
		sample := g.calls
		if len(sample) > 6 {
			sample = sample[:6]
		}

		t.Logf(
			"FDE [%#x,%#x): untraced=%d "+
				"recovered-entry=%t unresolved-owned-edges=%d "+
				"sample-calls=%#v",
			g.start,
			g.end,
			len(g.calls),
			g.recovered,
			g.unresolved,
			sample,
		)
	}

	t.Logf(
		"TOTAL: untraced=%d inside-FDE=%d "+
			"outside-FDE=%d affected-FDEs=%d",
		len(result.DataFlow.UntracedCalls),
		insideCount,
		len(outside),
		len(groups),
	)

	t.Logf("OUTSIDE FDE addresses: %#v", outside)

	if insideCount+len(outside) !=
		len(result.DataFlow.UntracedCalls) {
		t.Fatal("classification mismatch")
	}
}
