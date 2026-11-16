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

func TestProbeLargeFrameIndirectEdges(t *testing.T) {
	const start uint64 = 0x1540
	const end uint64 = 0x3903

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
		file, uint64(info.Size()),
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

	for gi, graph := range graphs {
		if graph.Name != ".text" {
			continue
		}

		reached := make(map[int]bool)
		found := false

		for _, fn := range recovered {
			if fn.Graph != gi || fn.Entry != start {
				continue
			}

			found = true
			for _, id := range fn.Blocks {
				reached[id] = true
			}
		}

		if !found {
			t.Fatal("target FDE function not recovered")
		}

		var totalBlocks, detachedBlocks int
		var indirectReached, indirectDetached int
		var directIntoDetached int
		printed := 0

		inFrame := func(block cfg.Block) bool {
			return block.Start >= start &&
				block.End <= end
		}

		for id, block := range graph.Blocks {
			if !inFrame(block) {
				continue
			}

			totalBlocks++

			if !reached[id] {
				detachedBlocks++
			}
		}

		for _, edge := range graph.Edges {
			if edge.From < 0 ||
				edge.From >= len(graph.Blocks) {
				continue
			}

			source := graph.Blocks[edge.From]

			if !inFrame(source) {
				continue
			}

			if edge.Kind == cfg.EdgeIndirect &&
				edge.To == -1 {

				if reached[edge.From] {
					indirectReached++
				} else {
					indirectDetached++
				}

				if printed < 15 &&
					len(source.Instructions) > 0 {

					inst := source.Instructions[len(source.Instructions)-1]

					t.Logf(
						"INDIRECT: reached=%t "+
							"block=%#x instruction=%#x "+
							"mnemonic=%s operands=%+v",
						reached[edge.From],
						source.Start,
						inst.Address,
						inst.Mnemonic,
						inst.Operands,
					)
					printed++
				}
			}

			if edge.To >= 0 &&
				edge.To < len(graph.Blocks) &&
				reached[edge.From] &&
				!reached[edge.To] &&
				inFrame(graph.Blocks[edge.To]) {

				directIntoDetached++

				if printed < 15 {
					t.Logf(
						"RESOLVED EDGE INTO DETACHED: "+
							"from=%#x to=%#x kind=%s",
						source.Start,
						graph.Blocks[edge.To].Start,
						edge.Kind,
					)
					printed++
				}
			}
		}

		t.Logf(
			"FRAME [%#x,%#x): "+
				"blocks=%d reached=%d detached=%d",
			start,
			end,
			totalBlocks,
			totalBlocks-detachedBlocks,
			detachedBlocks,
		)

		t.Logf(
			"EDGES: unresolved-indirect-reached=%d "+
				"unresolved-indirect-detached=%d "+
				"resolved-into-detached=%d",
			indirectReached,
			indirectDetached,
			directIntoDetached,
		)

		return
	}

	t.Fatal(".text CFG not found")
}

func TestProbeJumpRAXProducer(t *testing.T) {
	const jumpAddress uint64 = 0x16da

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

	var graph *cfg.Graph
	jumpBlock := -1

	for gi := range graphs {
		g := &graphs[gi]

		for bi, block := range g.Blocks {
			for _, inst := range block.Instructions {
				if inst.Address == jumpAddress &&
					inst.Flow == decoder.FlowJump &&
					inst.Indirect {
					graph = g
					jumpBlock = bi
					break
				}
			}
		}
	}

	if graph == nil {
		t.Fatal("indirect JMP at 0x16da not found")
	}

	t.Logf(
		"DISPATCH: region=%s block=%#x address=%#x",
		graph.Name,
		graph.Blocks[jumpBlock].Start,
		jumpAddress,
	)

	// Show the instructions preceding the indirect jump.
	// This is needed to establish where RAX comes from.
	for _, section := range decoded.Sections {
		if section.Index != graph.Section {
			continue
		}

		var preceding []decoder.Instruction

		for _, inst := range section.Instructions {
			if inst.Address >= 0x1540 &&
				inst.Address <= jumpAddress {
				preceding = append(preceding, inst)
			}
		}

		if len(preceding) > 50 {
			preceding = preceding[len(preceding)-50:]
		}

		t.Log("INSTRUCTIONS BEFORE JMP RAX:")

		for _, inst := range preceding {
			t.Logf(
				"%#x: %-10s operands=%+v bytes=% x",
				inst.Address,
				inst.Mnemonic,
				inst.Operands,
				inst.Bytes,
			)

			// Inspect candidate RIP-relative table bases.
			if inst.Mnemonic != "LEA" ||
				len(inst.Operands) != 2 {
				continue
			}

			mem := inst.Operands[1]

			if mem.Kind != decoder.OperandMemory ||
				mem.Memory.Base != "RIP" {
				continue
			}

			base := int64(inst.Address) +
				int64(inst.Size) +
				mem.Memory.Displacement

			if base < 0 {
				continue
			}

			raw, err := parsed.Image.ReadVirtual(
				uint64(base), 32,
			)

			if err != nil {
				t.Logf(
					"  RIP target %#x not readable: %v",
					uint64(base), err,
				)
				continue
			}

			t.Logf(
				"  RIP target=%#x data=% x",
				uint64(base),
				raw,
			)
		}

		break
	}

	// Follow resolved predecessor edges backward to inspect
	// instructions that may define RAX in earlier blocks.
	type node struct {
		id    int
		depth int
	}

	seen := map[int]bool{jumpBlock: true}
	queue := []node{{id: jumpBlock}}

	t.Log("PREDECESSOR BLOCKS:")

	for len(queue) > 0 && len(seen) < 12 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= 3 {
			continue
		}

		for _, edge := range graph.Edges {
			if edge.To != current.id ||
				edge.From < 0 ||
				edge.From >= len(graph.Blocks) {
				continue
			}

			if seen[edge.From] {
				continue
			}

			seen[edge.From] = true

			block := graph.Blocks[edge.From]

			t.Logf(
				"PREDECESSOR depth=%d block=[%#x,%#x) edge=%s",
				current.depth+1,
				block.Start,
				block.End,
				edge.Kind,
			)

			insts := block.Instructions
			if len(insts) > 12 {
				insts = insts[len(insts)-12:]
			}

			for _, inst := range insts {
				t.Logf(
					"  %#x: %-10s operands=%+v bytes=% x",
					inst.Address,
					inst.Mnemonic,
					inst.Operands,
					inst.Bytes,
				)
			}

			queue = append(queue, node{
				id:    edge.From,
				depth: current.depth + 1,
			})

			if len(seen) >= 12 {
				break
			}
		}
	}
}
