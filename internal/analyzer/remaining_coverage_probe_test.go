package analyzer_test

import (
	"sort"
	"testing"

	"bininspect/internal/collect"
)

func TestProbeRemainingCoverage(t *testing.T) {
	result, err := collect.Engine("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}

	type component struct {
		region string
		start  uint64
		end    uint64
		blocks int
		calls  int
	}

	var components []component
	totalUnownedCalls := 0
	unresolvedOwnedJumps := 0

	for gi, graph := range result.Graphs {
		owned := make([]bool, len(graph.Blocks))

		for _, fn := range result.Functions {
			if fn.Graph != gi {
				continue
			}

			for _, id := range fn.Blocks {
				if id >= 0 && id < len(owned) {
					owned[id] = true
				}
			}
		}

		callsPerBlock := make([]int, len(graph.Blocks))

		for _, call := range graph.Calls {
			for id, block := range graph.Blocks {
				if call.Address >= block.Start &&
					call.Address < block.End {

					if !owned[id] {
						callsPerBlock[id]++
						totalUnownedCalls++
					}
					break
				}
			}
		}

		adj := make([][]int, len(graph.Blocks))

		for _, edge := range graph.Edges {
			if edge.From < 0 ||
				edge.From >= len(graph.Blocks) {
				continue
			}

			if edge.To == -1 && owned[edge.From] {
				unresolvedOwnedJumps++

				if unresolvedOwnedJumps <= 12 {
					t.Logf(
						"UNRESOLVED FROM OWNED: "+
							"region=%s block=%#x kind=%s",
						graph.Name,
						graph.Blocks[edge.From].Start,
						edge.Kind,
					)
				}
				continue
			}

			if edge.To < 0 ||
				edge.To >= len(graph.Blocks) ||
				owned[edge.From] ||
				owned[edge.To] {
				continue
			}

			// Group blocks connected by a resolved CFG
			// edge, ignoring edge direction for grouping.
			adj[edge.From] = append(
				adj[edge.From], edge.To,
			)
			adj[edge.To] = append(
				adj[edge.To], edge.From,
			)
		}

		seen := make([]bool, len(graph.Blocks))

		for first := range graph.Blocks {
			if owned[first] || seen[first] {
				continue
			}

			item := component{
				region: graph.Name,
				start:  graph.Blocks[first].Start,
				end:    graph.Blocks[first].End,
			}

			queue := []int{first}
			seen[first] = true

			for len(queue) > 0 {
				id := queue[0]
				queue = queue[1:]

				block := graph.Blocks[id]

				item.blocks++
				item.calls += callsPerBlock[id]

				if block.Start < item.start {
					item.start = block.Start
				}
				if block.End > item.end {
					item.end = block.End
				}

				for _, next := range adj[id] {
					if seen[next] {
						continue
					}

					seen[next] = true
					queue = append(queue, next)
				}
			}

			if item.calls > 0 {
				components = append(components, item)
			}
		}
	}

	sort.Slice(components, func(i, j int) bool {
		if components[i].calls != components[j].calls {
			return components[i].calls > components[j].calls
		}
		return components[i].start < components[j].start
	})

	for i, c := range components {
		if i >= 15 {
			break
		}

		t.Logf(
			"UNOWNED COMPONENT: "+
				"region=%s range=[%#x,%#x) "+
				"blocks=%d calls=%d",
			c.region,
			c.start,
			c.end,
			c.blocks,
			c.calls,
		)
	}

	t.Logf(
		"TOTAL: unowned-calls=%d "+
			"components-with-calls=%d "+
			"unresolved-edges-from-owned=%d",
		totalUnownedCalls,
		len(components),
		unresolvedOwnedJumps,
	)
}
