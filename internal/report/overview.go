package report

import (
	"fmt"

	"bininspect/internal/analyzer"
)

func Overview(r analyzer.Result) {
	box("01  BINARY IDENTITY",
		fmt.Sprintf("Format:       %s", r.Info.Format),
		fmt.Sprintf("Architecture: %s", r.Info.Architecture),
		fmt.Sprintf("Class:        ELF%d", r.Info.Bits),
		fmt.Sprintf("Endianness:   %s", r.Info.Endianness),
		fmt.Sprintf("Type:         %s", r.ELFType),
		fmt.Sprintf("Entry point:  %#x", r.Info.Entry),
	)

	s := r.Structure

	box("02  BINARY STRUCTURE",
		fmt.Sprintf("Program headers:      %d", s.Programs),
		fmt.Sprintf("Section headers:      %d", s.Sections),
		fmt.Sprintf("Section symbols:       %d", s.Symbols),
		fmt.Sprintf("Dynamic symbols:       %d", s.DynamicSymbols),
		fmt.Sprintf("Section relocations:   %d", s.Relocations),
		fmt.Sprintf("Dynamic relocations:   %d", s.DynamicRelocations),
		fmt.Sprintf("Linked dependencies:   %d", s.Dependencies),
		"Note: section and dynamic datasets can overlap; counts are not additive.",
	)

	a := r.Assembly

	box("03  DECODED INSTRUCTION CANDIDATES",
		fmt.Sprintf("Instructions:          %d", a.CandidateInstructions),
		fmt.Sprintf("Calls:                 %d", a.Calls),
		fmt.Sprintf("Jumps:                 %d", a.Jumps),
		fmt.Sprintf("Conditional branches:  %d", a.ConditionalBranches),
		fmt.Sprintf("Returns:               %d", a.Returns),
		fmt.Sprintf("System instructions:   %d", a.SystemInstructions),
		fmt.Sprintf("Traps:                 %d", a.Traps),
		fmt.Sprintf("Undecoded bytes:       %d", a.SkippedBytes),
		fmt.Sprintf("Skipped data bytes:    %d", a.SkippedDataBytes),
		fmt.Sprintf("Decoder diagnostics:   %d", len(r.Diagnostics)),
	)

	graphs(r)
}

func graphs(r analyzer.Result) {
	blocks, edges, calls := 0, 0, 0

	for _, g := range r.Graphs {
		blocks += len(g.Blocks)
		edges += len(g.Edges)
		calls += len(g.Calls)
	}

	rows := []string{
		fmt.Sprintf("CFG regions:    %d", len(r.Graphs)),
		fmt.Sprintf("Basic blocks:   %d", blocks),
		fmt.Sprintf("Edges:          %d", edges),
		fmt.Sprintf("Call sites:     %d", calls),
		"",
		"Regions:",
	}

	for i, g := range r.Graphs {
		if !fullReport && i == 8 {
			rows = append(rows, fmt.Sprintf(
				"... %d additional regions omitted from terminal view",
				len(r.Graphs)-i,
			))
			break
		}

		rows = append(rows, fmt.Sprintf(
			"  [%d] %s — %d blocks, %d edges, %d calls",
			g.Section,
			reportText(g.Name, 30),
			len(g.Blocks),
			len(g.Edges),
			len(g.Calls),
		))

		if !fullReport {
			continue
		}

		for index, b := range g.Blocks {
			rows = append(rows, fmt.Sprintf(
				"    block %d: [%#x, %#x) — %d candidate instructions",
				index,
				b.Start,
				b.End,
				len(b.Instructions),
			))
		}

		for _, e := range g.Edges {
			destination := fmt.Sprintf(
				"external/unknown at %#x", e.Target,
			)

			if e.To >= 0 {
				destination = fmt.Sprintf("block %d", e.To)
			}

			if e.Symbol != "" {
				destination += " (" + e.Symbol + ")"
			}

			rows = append(rows, fmt.Sprintf(
				"    edge block %d: %s -> %s",
				e.From,
				e.Kind,
				destination,
			))
		}

		for _, call := range g.Calls {
			target := "unresolved"

			switch {
			case call.Symbol != "":
				target = "symbol " + call.Symbol
			case call.Indirect:
				target = "indirect"
			case call.HasTarget:
				target = fmt.Sprintf("%#x", call.Target)
			}

			rows = append(rows, fmt.Sprintf(
				"    call %#x -> %s",
				call.Address,
				target,
			))
		}
	}

	box("04  CONTROL FLOW", rows...)
}
