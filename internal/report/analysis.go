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

	total := len(r.DataFlow.Calls) +
		len(r.DataFlow.UntracedCalls)

	rows := []string{
		fmt.Sprintf(
			"Decoded call sites accounted for: %d",
			total,
		),
		fmt.Sprintf(
			"Calls with recovered-function data-flow traces: %d",
			len(r.DataFlow.Calls),
		),
		fmt.Sprintf(
			"Calls outside recovered-function data flow: %d",
			len(r.DataFlow.UntracedCalls),
		),
		fmt.Sprintf(
			"Modeled stack-depth observations: %d",
			len(r.DataFlow.Stack),
		),
		"Untraced call references have no inferred argument values.",
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

	if len(r.DataFlow.UntracedCalls) > 0 {
		rows = append(
			rows,
			"",
			"Unattributed call references:",
		)

		for i, call := range r.DataFlow.UntracedCalls {
			if !fullReport && i >= 8 {
				rows = append(rows, fmt.Sprintf(
					"... %d additional references in saved report",
					len(r.DataFlow.UntracedCalls)-i,
				))
				break
			}

			rows = append(rows, fmt.Sprintf(
				"  section %d, %#x -> %s (indirect=%t)",
				call.Section,
				call.Address,
				call.Target,
				call.Indirect,
			))
		}
	}
	box("06  DATA-FLOW ANALYSIS", rows...)
}
