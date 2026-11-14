package report

import (
	"fmt"

	"bininspect/internal/analyzer"
)

func Recovery(r analyzer.Result) {
	rows := []string{
		fmt.Sprintf(
			"Recovered function candidates: %d",
			len(r.Functions),
		),
		"Function boundaries are heuristic; shared blocks and unreachable code may be unresolved.",
	}

	for i, fn := range r.Functions {
		if !fullReport && i >= 12 {
			rows = append(rows, fmt.Sprintf(
				"... %d additional functions in saved report",
				len(r.Functions)-i,
			))
			break
		}

		rows = append(rows, fmt.Sprintf(
			"  %s at section %d, %#x (%s): %d blocks, %d instructions, %d calls",
			fn.Name,
			fn.Section,
			fn.Entry,
			fn.Source,
			len(fn.Blocks),
			fn.Instructions,
			len(fn.Calls),
		))
	}

	box("05  FUNCTION RECOVERY", rows...)
}

func DataFlow(r analyzer.Result) {
	if !r.DataFlow.Supported {
		box(
			"06  DATA-FLOW ANALYSIS",
			"Not supported for this architecture; typed decoding and CFG construction remain available.",
		)
		return
	}

	rows := []string{
		fmt.Sprintf(
			"Traced calls: %d",
			len(r.DataFlow.Calls),
		),
		fmt.Sprintf(
			"Modeled stack-depth observations: %d",
			len(r.DataFlow.Stack),
		),
		"Values are abstract facts, not proven runtime values or buffer bounds.",
	}

	for i, s := range r.DataFlow.Stack {
		if !fullReport && i >= 8 {
			rows = append(rows, fmt.Sprintf(
				"... %d additional stack observations in saved report",
				len(r.DataFlow.Stack)-i,
			))
			break
		}

		status := "partial: no"
		if s.Partial {
			status = "partial: yes"
		}

		rows = append(rows, fmt.Sprintf(
			"  %s (section %d, %#x): modeled depth %d bytes (%s)",
			s.Function,
			s.Section,
			s.Entry,
			s.MaxDepthBytes,
			status,
		))
	}

	if len(r.DataFlow.Calls) > 0 {
		rows = append(
			rows, "", "Call-site arguments with known values:",
		)
	}

	for i, call := range r.DataFlow.Calls {
		if !fullReport && i >= 12 {
			rows = append(rows, fmt.Sprintf(
				"... %d additional calls in saved report",
				len(r.DataFlow.Calls)-i,
			))
			break
		}

		rows = append(rows, fmt.Sprintf(
			"  %s: %#x -> %s",
			call.Function,
			call.Address,
			call.Target,
		))

		known := 0

		for _, arg := range call.Arguments {
			if arg.Value.Kind == "" {
				continue
			}

			known++

			if !fullReport && known > 3 {
				rows = append(
					rows,
					"    ... more arguments in saved report",
				)
				break
			}

			rows = append(rows, fmt.Sprintf(
				"    arg %d (%s): %s",
				arg.Position,
				arg.Location,
				arg.Value.String(),
			))
		}
	}

	box("06  DATA-FLOW ANALYSIS", rows...)
}
