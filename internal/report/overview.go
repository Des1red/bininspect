package report

import (
	"fmt"

	"bininspect/internal/analyzer"
)

func Overview(r analyzer.Result) {
	identity(r)
	structure(r)
	assembly(r)
	controlFlow(r)
	observations(r)
	analysisStatus()
}

func identity(r analyzer.Result) {
	box("01  BINARY IDENTITY",
		fmt.Sprintf("Format:       %s", r.Info.Format),
		fmt.Sprintf("Architecture: %s", r.Info.Architecture),
		fmt.Sprintf("Class:        ELF%d", r.Info.Bits),
		fmt.Sprintf("Endianness:   %s", r.Info.Endianness),
		fmt.Sprintf("ELF type:     %s", r.ELFType),
		fmt.Sprintf("Entry point:  %#x", r.Info.Entry),
	)
}

func structure(r analyzer.Result) {
	s := r.Structure

	box("02  ELF STRUCTURE",
		fmt.Sprintf("Program headers:        %d", s.Programs),
		fmt.Sprintf("Section headers:        %d", s.Sections),
		fmt.Sprintf("Section symbols:        %d", s.Symbols),
		fmt.Sprintf("Dynamic symbols:        %d", s.DynamicSymbols),
		fmt.Sprintf("Section relocations:    %d", s.Relocations),
		fmt.Sprintf("Dynamic relocations:    %d", s.DynamicRelocations),
		fmt.Sprintf("Dynamic dependencies:   %d", s.Dependencies),
		"Note: symbol and relocation sources may overlap.",
	)
}

func assembly(r analyzer.Result) {
	a := r.Assembly

	box("03  INSTRUCTION DECODING",
		fmt.Sprintf("Candidate instructions: %d", a.CandidateInstructions),
		fmt.Sprintf("Calls:                  %d", a.Calls),
		fmt.Sprintf("Jumps:                  %d", a.Jumps),
		fmt.Sprintf("Conditional branches:   %d", a.ConditionalBranches),
		fmt.Sprintf("Returns:                %d", a.Returns),
		fmt.Sprintf("System instructions:    %d", a.SystemInstructions),
		fmt.Sprintf("Traps:                  %d", a.Traps),
		fmt.Sprintf("Undecodable bytes:      %d", a.SkippedBytes),
		fmt.Sprintf("Recognized data bytes:  %d", a.SkippedDataBytes),
	)
}

func controlFlow(r analyzer.Result) {
	blocks, edges, calls := 0, 0, 0

	for _, graph := range r.Graphs {
		blocks += len(graph.Blocks)
		edges += len(graph.Edges)
		calls += len(graph.Calls)
	}

	rows := []string{
		fmt.Sprintf("Executable regions:  %d", len(r.Graphs)),
		fmt.Sprintf("Candidate blocks:    %d", blocks),
		fmt.Sprintf("CFG edges:           %d", edges),
		fmt.Sprintf("Recorded call sites: %d", calls),
	}

	if len(r.Graphs) > 0 {
		rows = append(rows, "", "Per-region breakdown:")
	}

	for i, graph := range r.Graphs {
		if !fullReport && i >= 8 {
			rows = append(rows, fmt.Sprintf(
				"... %d more regions in saved report",
				len(r.Graphs)-i,
			))
			break
		}

		rows = append(rows, fmt.Sprintf(
			"  [%d] %s: %d blocks, %d edges, %d calls",
			graph.Section,
			reportText(graph.Name, 24),
			len(graph.Blocks),
			len(graph.Edges),
			len(graph.Calls),
		))
	}

	box("04  CONTROL-FLOW CANDIDATES", rows...)
}

func observations(r analyzer.Result) {
	rows := []string{
		fmt.Sprintf("Decode diagnostics: %d", len(r.Diagnostics)),
		fmt.Sprintf("Parser warnings:    %d", len(r.Warnings)),
	}

	if len(r.Diagnostics) > 0 {
		rows = append(rows, "", "Decode diagnostics:")

		for i, d := range r.Diagnostics {
			if !fullReport && i >= 8 {
				rows = append(rows, fmt.Sprintf(
					"... %d more diagnostics in saved report",
					len(r.Diagnostics)-i,
				))
				break
			}

			rows = append(rows, fmt.Sprintf(
				"  section %d at %#x (%d bytes): %s",
				d.Section,
				d.Address,
				d.Size,
				reportText(d.Reason, 100),
			))
		}
	}

	if len(r.Warnings) > 0 {
		rows = append(rows, "", "ELF validation warnings:")

		for i, warning := range r.Warnings {
			if !fullReport && i >= 8 {
				rows = append(rows, fmt.Sprintf(
					"... %d more warnings in saved report",
					len(r.Warnings)-i,
				))
				break
			}

			rows = append(rows,
				"  "+reportText(warning, 120),
			)
		}
	}

	box("05  DIAGNOSTICS AND WARNINGS", rows...)
}

func analysisStatus() {
	box("06  ANALYSIS COVERAGE",
		"Available: ELF identity and structure, decoded instruction candidates, basic-block graphs, and diagnostic evidence.",
		"Not yet implemented: function recovery, interprocedural call graphs, register/stack data flow, security-protection evaluation, and vulnerability findings.",
		"A linear-sweep instruction candidate is not necessarily reachable executable code. No security conclusion is drawn from analyses that have not run.",
	)
}
