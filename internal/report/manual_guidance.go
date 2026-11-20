package report

import (
	"fmt"

	"bininspect/internal/analyzer/findings"
)

func renderManualGuidance(
	guide *findings.ManualGuidance,
) {
	if guide == nil {
		return
	}

	rows := []string{
		"",
		"MANUAL EXPLOITATION GUIDANCE",
		"Status: " + guide.Status,
		"",
		"Hypothesis: " + guide.Hypothesis,
		"",
	}

	for i, step := range guide.Steps {
		rows = append(
			rows,
			fmt.Sprintf(
				"Step %d: %s",
				i+1,
				step,
			),
		)
	}

	rows = append(
		rows,
		"",
		"Expected evidence: "+guide.Expected,
		"Limitations: "+guide.Limitations,
	)

	for _, row := range rows {
		for _, line := range wrap(row, width-2) {
			boxLine(line)
		}
	}
}
