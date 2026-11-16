package analyzer_test

import (
	"os"
	"sort"
	"testing"

	"bininspect/internal/analyzer/functions"
	"bininspect/internal/binary"
	"bininspect/internal/collect"
)

func TestProbeOwnershipBoundaries(t *testing.T) {
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

	parsed, err := binary.Engine(
		file,
		uint64(info.Size()),
	)
	if err != nil {
		t.Fatal(err)
	}

	frames := functions.UnwindRanges(parsed)

	frameAt := func(address uint64) (functions.UnwindRange, bool) {
		for _, frame := range frames {
			if address >= frame.Start &&
				address < frame.End {
				return frame, true
			}
		}
		return functions.UnwindRange{}, false
	}

	type blockKey struct {
		graph int
		block int
	}

	owners := make(map[blockKey][]*functions.Function)

	for i := range result.Functions {
		fn := &result.Functions[i]

		for _, id := range fn.Blocks {
			key := blockKey{fn.Graph, id}
			owners[key] = append(owners[key], fn)
		}
	}

	counts := make(map[string]int)
	destinations := make(map[blockKey]bool)

	total := 0
	printed := 0

	for gi, graph := range result.Graphs {
		for _, edge := range graph.Edges {
			if edge.From < 0 ||
				edge.To < 0 ||
				edge.From >= len(graph.Blocks) ||
				edge.To >= len(graph.Blocks) {
				continue
			}

			sourceKey := blockKey{gi, edge.From}
			destKey := blockKey{gi, edge.To}

			sourceOwners := owners[sourceKey]
			destOwners := owners[destKey]

			if len(sourceOwners) == 0 ||
				len(destOwners) != 0 {
				continue
			}

			total++
			destinations[destKey] = true

			source := graph.Blocks[edge.From]
			dest := graph.Blocks[edge.To]

			sourceFrame, sourceHas := frameAt(source.Start)
			destFrame, destHas := frameAt(dest.Start)

			category := ""

			switch {
			case sourceHas && destHas &&
				sourceFrame == destFrame:
				category = "same-FDE"

			case sourceHas && destHas:
				category = "different-FDE"

			case sourceHas:
				category = "leaves-FDE"

			case destHas:
				category = "enters-FDE"

			default:
				category = "outside-FDE"
			}

			counts[category]++

			calls := 0

			for _, call := range graph.Calls {
				if call.Address >= dest.Start &&
					call.Address < dest.End {
					calls++
				}
			}

			if printed < 35 {
				fn := sourceOwners[0]

				t.Logf(
					"%s: edge=%s "+
						"from=[%#x,%#x) "+
						"to=[%#x,%#x) "+
						"owner=%s entry=%#x source=%s "+
						"source-FDE=[%#x,%#x) "+
						"dest-FDE=[%#x,%#x) "+
						"dest-calls=%d",
					category,
					edge.Kind,
					source.Start,
					source.End,
					dest.Start,
					dest.End,
					fn.Name,
					fn.Entry,
					fn.Source,
					sourceFrame.Start,
					sourceFrame.End,
					destFrame.Start,
					destFrame.End,
					calls,
				)

				printed++
			}
		}
	}

	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	t.Log("BOUNDARY CLASSIFICATION:")

	for _, key := range keys {
		t.Logf("  %-20s %d", key, counts[key])
	}

	t.Logf(
		"TOTAL: owned-to-unowned-edges=%d "+
			"unique-destination-blocks=%d",
		total,
		len(destinations),
	)

	if total != 42 {
		t.Logf(
			"NOTE: previous probe reported 42; "+
				"current analysis reports %d",
			total,
		)
	}
}
