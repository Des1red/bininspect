package analyzer_test

import (
	"testing"

	"bininspect/internal/collect"
)

func TestProbeCallCoverage(t *testing.T) {
	result, err := collect.Engine("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}

	type blockKey struct {
		graph int
		block int
	}

	type callKey struct {
		section int
		address uint64
	}

	// Record which recovered functions own each CFG block.
	owners := make(map[blockKey][]string)

	for _, fn := range result.Functions {
		if fn.Graph < 0 || fn.Graph >= len(result.Graphs) {
			t.Fatalf("invalid graph for function %s", fn.Name)
		}

		for _, block := range fn.Blocks {
			if block < 0 ||
				block >= len(result.Graphs[fn.Graph].Blocks) {
				t.Fatalf("invalid block for %s", fn.Name)
			}

			key := blockKey{fn.Graph, block}
			owners[key] = append(owners[key], fn.Name)
		}
	}

	// Record unique data-flow call sites.
	traced := make(map[callKey]bool)

	for _, call := range result.DataFlow.Calls {
		traced[callKey{
			section: call.Section,
			address: call.Address,
		}] = true
	}

	var total, covered int
	var unowned, ownedButUntraced, missingBlock int
	var multipleOwners int
	printed := 0

	for gi, graph := range result.Graphs {
		graphCovered := 0
		graphUnowned := 0
		graphUntraced := 0

		for _, call := range graph.Calls {
			total++

			key := callKey{
				section: graph.Section,
				address: call.Address,
			}

			blockID := -1

			for bi, block := range graph.Blocks {
				if call.Address >= block.Start &&
					call.Address < block.End {
					blockID = bi
					break
				}
			}

			if blockID < 0 {
				missingBlock++
				continue
			}

			callOwners := owners[blockKey{gi, blockID}]

			if len(callOwners) > 1 {
				multipleOwners++
			}

			if traced[key] {
				covered++
				graphCovered++
				continue
			}

			if len(callOwners) == 0 {
				unowned++
				graphUnowned++
			} else {
				ownedButUntraced++
				graphUntraced++
			}

			if printed < 20 {
				t.Logf(
					"UNTRACED: region=%s section=%d "+
						"call=%#x block=%#x "+
						"owners=%v target=%#x indirect=%t",
					graph.Name,
					graph.Section,
					call.Address,
					graph.Blocks[blockID].Start,
					callOwners,
					call.Target,
					call.Indirect,
				)
				printed++
			}
		}

		t.Logf(
			"REGION %-12s calls=%d traced=%d "+
				"unowned=%d owned-untraced=%d",
			graph.Name,
			len(graph.Calls),
			graphCovered,
			graphUnowned,
			graphUntraced,
		)
	}

	t.Logf(
		"TOTAL: decoded=%d traced=%d "+
			"unowned=%d owned-untraced=%d "+
			"missing-block=%d multi-owner=%d",
		total,
		covered,
		unowned,
		ownedButUntraced,
		missingBlock,
		multipleOwners,
	)

	t.Logf(
		"DATAFLOW records=%d unique=%d",
		len(result.DataFlow.Calls),
		len(traced),
	)

	if total != covered+unowned+
		ownedButUntraced+missingBlock {
		t.Fatal("call coverage accounting mismatch")
	}
}
