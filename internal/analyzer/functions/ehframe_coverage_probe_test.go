package functions

import (
	"os"
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestProbeUnownedFrameCoverage(t *testing.T) {
	file, err := os.Open("/bin/ls")
	if err != nil {
		t.Skip(err)
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

	decoded, err := decoder.Engine(parsed)
	if err != nil {
		t.Fatal(err)
	}

	graphs, err := cfg.BuildWithLeaders(
		decoded,
		Leaders(parsed, decoded),
	)
	if err != nil {
		t.Fatal(err)
	}

	recovered := Recover(parsed, graphs)
	ranges := UnwindRanges(parsed)

	type blockKey struct {
		graph int
		block int
	}

	owners := make(map[blockKey]int)

	for _, fn := range recovered {
		for _, block := range fn.Blocks {
			owners[blockKey{
				graph: fn.Graph,
				block: block,
			}]++
		}
	}

	var traced, unowned int
	var acceptedDisconnected int
	var acceptedBoundary int
	var rejectedFDE int
	var outsideFDE int
	var missingBlock int
	var multiOwner int

	acceptedTotal := 0
	printed := 0

	for gi, graph := range graphs {
		accepted := frameBounds(graph, ranges)
		acceptedTotal += len(accepted)

		for _, call := range graph.Calls {
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

			count := owners[blockKey{gi, blockID}]

			if count > 1 {
				multiOwner++
			}

			if count > 0 {
				traced++
				continue
			}

			unowned++

			block := graph.Blocks[blockID]
			category := ""
			var rangeStart, rangeEnd uint64

			for start, end := range accepted {
				if call.Address >= start &&
					call.Address < end {
					rangeStart = start
					rangeEnd = end

					if block.Start >= start &&
						block.End <= end {
						category = "accepted-disconnected"
						acceptedDisconnected++
					} else {
						category = "accepted-boundary"
						acceptedBoundary++
					}
					break
				}
			}

			if category == "" {
				for _, r := range ranges {
					if call.Address >= r.Start &&
						call.Address < r.End {
						category = "rejected-FDE"
						rangeStart = r.Start
						rangeEnd = r.End
						rejectedFDE++
						break
					}
				}
			}

			if category == "" {
				category = "outside-FDE"
				outsideFDE++
			}

			if printed < 25 {
				t.Logf(
					"%s: call=%#x block=[%#x,%#x) "+
						"FDE=[%#x,%#x) region=%s",
					category,
					call.Address,
					block.Start,
					block.End,
					rangeStart,
					rangeEnd,
					graph.Name,
				)
				printed++
			}
		}
	}

	t.Logf(
		"FDE: raw=%d accepted-across-regions=%d functions=%d",
		len(ranges),
		acceptedTotal,
		len(recovered),
	)

	t.Logf(
		"CALLS: owned=%d unowned=%d "+
			"accepted-disconnected=%d "+
			"accepted-boundary=%d "+
			"rejected-FDE=%d outside-FDE=%d "+
			"missing-block=%d multi-owner=%d",
		traced,
		unowned,
		acceptedDisconnected,
		acceptedBoundary,
		rejectedFDE,
		outsideFDE,
		missingBlock,
		multiOwner,
	)

	if unowned != acceptedDisconnected+
		acceptedBoundary+
		rejectedFDE+
		outsideFDE {
		t.Fatal("unowned call classification mismatch")
	}
}
