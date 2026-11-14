package report

import (
	"fmt"
	"strings"

	"bininspect/internal/analyzer"
)

const maxFindings = 10

func Findings(r analyzer.Result) {
	counts := map[string]int{}

	for _, finding := range r.Findings {
		counts[strings.ToLower(finding.Severity)]++
	}

	box(
		"08  SECURITY FINDINGS",
		fmt.Sprintf(
			"Total: %d | High: %d | Medium: %d | Low: %d | Informational: %d",
			len(r.Findings),
			counts["high"],
			counts["medium"],
			counts["low"],
			counts["info"],
		),
		"API findings identify code requiring review; no finding proves exploitability.",
	)

	if len(r.Findings) == 0 {
		box(
			"NO OBSERVED FINDINGS",
			"No issue matched the implemented rules. This does not prove the binary is secure.",
		)
		return
	}

	for i, finding := range r.Findings {
		if !fullReport && i >= maxFindings {
			emitf(
				"... %d additional findings in saved report\n",
				len(r.Findings)-i,
			)
			break
		}

		rows := []string{
			"ID: " + finding.ID,
			"Category: " + finding.Category,
			"Severity: " + paint(
				statusColor(finding.Severity),
				strings.ToUpper(finding.Severity),
			),
			"Confidence (in evidence): " + finding.Confidence,
			"Description: " + finding.Description,
		}

		if finding.HasAddress {
			rows = append(rows, fmt.Sprintf(
				"Location: section %d, %#x",
				finding.Section,
				finding.Address,
			))
		}

		for j, evidence := range finding.Evidence {
			if !fullReport && j >= 3 {
				rows = append(rows, fmt.Sprintf(
					"... %d more evidence entries in saved report",
					len(finding.Evidence)-j,
				))
				break
			}

			rows = append(rows, "Evidence: "+evidence)
		}

		rows = append(
			rows,
			"Recommendation: "+finding.Recommendation,
		)

		box(
			fmt.Sprintf(
				"FINDING %02d  %s",
				i+1,
				finding.Title,
			),
			rows...,
		)
	}
}
