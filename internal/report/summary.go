package report

import (
	"fmt"

	"bininspect/internal/analyzer"
)

func Summary(r analyzer.Result) {
	rows := []string{
		fmt.Sprintf(
			"BinInspect decoded %d candidate instructions across %d CFG regions and recovered %d function candidates.",
			r.Assembly.CandidateInstructions,
			len(r.Graphs),
			len(r.Functions),
		),
		fmt.Sprintf(
			"Call-argument tracing: supported=%t; %d traced sites; %d stack-depth observations.",
			r.DataFlow.Supported,
			len(r.DataFlow.Calls),
			len(r.DataFlow.Stack),
		),
		fmt.Sprintf(
			"Recorded findings: %d. No rule alone establishes an exploitable vulnerability.",
			len(r.Findings),
		),
		fmt.Sprintf(
			"Security indicators: NX=%s; PIE=%s; RELRO=%s; canary=%s; FORTIFY=%s; ASLR=%s; RWX=%s.",
			r.Security.NX.Status,
			r.Security.PIE.Status,
			r.Security.RELRO.Status,
			r.Security.Canary.Status,
			r.Security.Fortify.Status,
			r.Security.ASLR.Status,
			r.Security.RWX.Status,
		),
		fmt.Sprintf(
			"Decoder skipped %d undecodable bytes and %d known data bytes.",
			r.Assembly.SkippedBytes,
			r.Assembly.SkippedDataBytes,
		),
		"Limitations: linear-sweep instructions are candidates; function recovery is heuristic; data flow models selected x86/x64 instructions; ELF hardening flags do not prove runtime enforcement.",
	}

	if len(r.Warnings) > 0 {
		rows = append(
			rows, "",
			fmt.Sprintf("Warnings: %d", len(r.Warnings)),
		)

		for i, warning := range r.Warnings {
			if !fullReport && i >= 5 {
				rows = append(rows, fmt.Sprintf(
					"... %d more warnings in saved report",
					len(r.Warnings)-i,
				))
				break
			}

			rows = append(rows, "  "+warning)
		}
	}

	if len(r.Diagnostics) > 0 {
		rows = append(
			rows, "",
			fmt.Sprintf(
				"Decoder diagnostics: %d",
				len(r.Diagnostics),
			),
		)

		for i, d := range r.Diagnostics {
			if !fullReport && i >= 5 {
				rows = append(rows, fmt.Sprintf(
					"... %d more diagnostics in saved report",
					len(r.Diagnostics)-i,
				))
				break
			}

			rows = append(rows, fmt.Sprintf(
				"  section %d at %#x: %s",
				d.Section,
				d.Address,
				d.Reason,
			))
		}
	}

	box("09  ANALYSIS SUMMARY", rows...)
}
