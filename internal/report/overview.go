package report

import (
	"fmt"
	"sort"
	"strings"

	"bininspect/internal/models"
)

func Overview(r models.ResultsModel) {
	identity(r.Identity)
	structure(r.Structure)
	assembly(r.Assembly)
	functions(r.Functions, r.FunctionDefinitions)
	sources(r.Sources)
}

func identity(id models.BinaryIdentity) {
	box("01  BINARY IDENTITY",
		"Format:       "+id.Format,
		"Architecture: "+id.Architecture,
		"Class:        "+id.Class,
		"Endianness:   "+id.Endianness,
		"Type:         "+id.Type,
		"Entry point:  "+id.EntryPoint,
	)
}

func structure(s models.BinaryStructure) {
	rows := []string{
		fmt.Sprintf("Sections:      %d", len(s.Sections)),
		fmt.Sprintf("Segments:      %d", len(s.Segments)),
		fmt.Sprintf("Symbols:       %d", len(s.Symbols)),
		fmt.Sprintf("Relocations:   %d", s.Relocations),
		fmt.Sprintf("Libraries:     %d", len(s.Libraries)),
		fmt.Sprintf("Debug info:    %t", s.DebugInfo),
	}

	if len(s.Libraries) > 0 {
		rows = append(rows, "", "Dependencies:")

		for i, library := range s.Libraries {
			if i == 5 {
				rows = append(rows,
					fmt.Sprintf("... and %d more", len(s.Libraries)-i))
				break
			}

			rows = append(rows, "  "+short(library, 65))
		}
	}

	box("02  BINARY STRUCTURE", rows...)
}

func assembly(a models.AssemblyAnalysis) {
	rows := []string{
		fmt.Sprintf("Instructions:  %d", len(a.Instructions)),
		fmt.Sprintf("Calls:         %d", a.Calls),
		fmt.Sprintf("Branches:      %d", a.Branches),
		fmt.Sprintf("Returns:       %d", a.Returns),
		fmt.Sprintf("Stack changes: %d", len(a.StackAllocations)),
	}

	if len(a.StackAllocations) > 0 {
		rows = append(rows, "", "Stack allocations:")

		for i, allocation := range a.StackAllocations {
			if i == 5 {
				rows = append(rows,
					fmt.Sprintf("... and %d more",
						len(a.StackAllocations)-i))
				break
			}

			rows = append(rows, fmt.Sprintf(
				"  0x%s  %d bytes  %s",
				allocation.Address,
				allocation.Size,
				short(allocation.Function, 28),
			))
		}
	}

	box("03  ASSEMBLY ANALYSIS", rows...)
}

func functions(
	calls []models.FunctionCall,
	definitions []models.FunctionInfo,
) {
	rows := []string{
		fmt.Sprintf("Functions discovered: %d", len(definitions)),
		fmt.Sprintf("Call sites:           %d", len(calls)),
	}

	uniqueCalls := make(map[string]int)
	unresolved := 0

	for _, call := range calls {
		if call.Indirect || call.Name == "" {
			unresolved++
			continue
		}

		uniqueCalls[call.Name]++
	}

	rows = append(rows,
		fmt.Sprintf("Unique callees:      %d", len(uniqueCalls)),
		fmt.Sprintf("Unresolved calls:    %d", unresolved),
	)

	type entry struct {
		name  string
		count int
	}

	var entries []entry

	for name, count := range uniqueCalls {
		entries = append(entries, entry{name, count})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count == entries[j].count {
			return entries[i].name < entries[j].name
		}
		return entries[i].count > entries[j].count
	})

	if len(entries) > 0 {
		rows = append(rows, "", "Most referenced functions:")
	}

	for i, item := range entries {
		if i == 8 {
			rows = append(rows, fmt.Sprintf(
				"... and %d more", len(entries)-i,
			))
			break
		}

		rows = append(rows, fmt.Sprintf(
			"  %-40s %d calls",
			short(item.name, 40),
			item.count,
		))
	}

	box("04  FUNCTION ANALYSIS", rows...)
}

func sources(sources map[string]models.SourceSummary) {
	names := make([]string, 0, len(sources))

	for name := range sources {
		names = append(names, name)
	}

	sort.Strings(names)

	available := 0
	var missing []string

	for _, name := range names {
		if sources[name].Available {
			available++
		} else {
			missing = append(missing, name)
		}
	}

	rows := []string{
		fmt.Sprintf(
			"Available datasets: %d/%d",
			available, len(names),
		),
	}

	if len(missing) > 0 {
		rows = append(rows, "Unavailable / empty:")
		rows = append(rows, "  "+short(
			strings.Join(missing, ", "), 65,
		))
	}

	box("05  COLLECTION COVERAGE", rows...)
}
