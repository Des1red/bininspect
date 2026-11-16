package analyzer_test

import (
	"sort"
	"testing"

	"bininspect/internal/collect"
)

func TestProbeUnresolvedEdgeTypes(t *testing.T) {
	result, err := collect.Engine("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}

	counts := make(map[string]int)
	printed := make(map[string]int)

	var ownedToUnowned int
	var total int

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

		for _, edge := range graph.Edges {
			if edge.From < 0 ||
				edge.From >= len(graph.Blocks) {
				continue
			}

			if edge.To >= 0 &&
				edge.To < len(graph.Blocks) {
				if owned[edge.From] && !owned[edge.To] {
					ownedToUnowned++
				}
				continue
			}

			if edge.To != -1 || !owned[edge.From] {
				continue
			}

			total++

			block := graph.Blocks[edge.From]
			if len(block.Instructions) == 0 {
				counts["empty-source"]++
				continue
			}

			inst := block.Instructions[len(block.Instructions)-1]

			category := "unknown-target"
			destinationRegion := ""

			switch {
			case inst.Indirect:
				category = "indirect"

			case !inst.HasTarget:
				category = "no-decoded-target"

			default:
				category = "outside-decoded-regions"

				found := false

				for otherGI, other := range result.Graphs {
					for _, destination := range other.Blocks {
						if inst.Target < destination.Start ||
							inst.Target >= destination.End {
							continue
						}

						destinationRegion = other.Name

						switch {
						case otherGI != gi:
							category = "cross-region"

						case inst.Target == destination.Start:
							category = "same-region-block-start"

						default:
							category = "same-region-block-interior"
						}

						found = true
						break
					}

					if found {
						break
					}
				}
			}

			key := string(edge.Kind) + "/" + category
			counts[key]++

			if printed[key] < 5 {
				t.Logf(
					"EDGE: region=%s source=%#x "+
						"kind=%s category=%s "+
						"inst=%#x %s "+
						"target=%#x destination-region=%s "+
						"bytes=% x operands=%+v",
					graph.Name,
					block.Start,
					edge.Kind,
					category,
					inst.Address,
					inst.Mnemonic,
					inst.Target,
					destinationRegion,
					inst.Bytes,
					inst.Operands,
				)

				printed[key]++
			}
		}
	}

	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	t.Log("UNRESOLVED EDGE CLASSIFICATION:")

	for _, key := range keys {
		t.Logf("  %-40s %d", key, counts[key])
	}

	t.Logf(
		"TOTAL: unresolved-from-owned=%d "+
			"resolved-owned-to-unowned=%d",
		total,
		ownedToUnowned,
	)
}
