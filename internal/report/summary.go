package report

import (
	"fmt"

	"bininspect/internal/analyzer"
)

func Summary(r analyzer.Result) {
	rows := []string{
		fmt.Sprintf(
			"The ELF decoder produced %d candidate instructions across %d CFG regions.",
			r.Assembly.CandidateInstructions,
			len(r.Graphs),
		),
		"Basic blocks and edges are preliminary. Linear-sweep decoding may include data or unreachable instructions.",
		"Function recovery, advanced data flow, protection checks, and vulnerability findings are not yet evaluated.",
		fmt.Sprintf(
			"Decoding skipped %d undecodable bytes and %d embedded-data bytes.",
			r.Assembly.SkippedBytes,
			r.Assembly.SkippedDataBytes,
		),
	}

	if len(r.Warnings) > 0 {
		rows = append(rows, "", fmt.Sprintf(
			"Parser warnings: %d", len(r.Warnings),
		))

		for i, warning := range r.Warnings {
			if !fullReport && i == 5 {
				rows = append(rows, fmt.Sprintf(
					"... %d additional warnings in saved report",
					len(r.Warnings)-i,
				))
				break
			}

			rows = append(rows, "  "+warning)
		}
	}

	if len(r.Diagnostics) > 0 {
		rows = append(rows, "", fmt.Sprintf(
			"Decoder diagnostics: %d",
			len(r.Diagnostics),
		))

		for i, d := range r.Diagnostics {
			if !fullReport && i == 5 {
				rows = append(rows, fmt.Sprintf(
					"... %d additional diagnostics in saved report",
					len(r.Diagnostics)-i,
				))
				break
			}

			rows = append(rows, fmt.Sprintf(
				"  section %d at %#x (%d bytes): %s",
				d.Section,
				d.Address,
				d.Size,
				d.Reason,
			))
		}
	}

	summaryBox("07  ANALYSIS SUMMARY", rows...)
}
