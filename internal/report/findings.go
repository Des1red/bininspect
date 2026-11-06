package report

import (
	"fmt"
	"sort"
	"strings"

	"bininspect/internal/models"
)

const maxFindings = 10

func Findings(r models.ResultsModel) {
	findings := append([]models.Finding(nil), r.Findings...)

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) >
			severityRank(findings[j].Severity)
	})

	header("07  SECURITY FINDINGS")

	if len(findings) == 0 {
		box("NO FINDINGS",
			"No potential security issues were identified.",
			"This does not prove that the binary is secure.",
		)
		return
	}

	counts := make(map[string]int)

	for _, finding := range findings {
		counts[strings.ToLower(finding.Severity)]++
	}

	emitf(
		"Total: %d | Critical: %d | High: %d | Medium: %d | Low: %d\n\n",
		len(findings),
		counts["critical"],
		counts["high"],
		counts["medium"],
		counts["low"],
	)

	for i, finding := range findings {
		if !fullReport && i >= maxFindings {
			emitf(
				"\n... %d additional findings omitted from terminal view\n",
				len(findings)-maxFindings,
			)
			break
		}

		printFinding(i+1, finding)
	}
}

func printFinding(index int, finding models.Finding) {
	severity := strings.ToUpper(finding.Severity)

	emitln("┌" + strings.Repeat("─", width) + "┐")

	title := fmt.Sprintf(
		"FINDING %02d  [%s]  %s",
		index,
		severity,
		reportText(finding.ID, 30),
	)

	boxLine(paint(statusColor(finding.Severity), title))

	emitln("├" + strings.Repeat("─", width) + "┤")
	if fullReport {
		findingRows("ID", finding.ID)
	}
	findingRows("Category", finding.Category)
	findingRows("Severity", severity)
	findingRows("Confidence", finding.Confidence)

	boxLine("")
	findingRows("Description", finding.Description)
	boxLine("")
	findingRows("Evidence", finding.Evidence)
	boxLine("")
	findingRows("Recommendation", finding.Recommendation)

	emitln("└" + strings.Repeat("─", width) + "┘")
}

func findingRows(label, value string) {
	if value == "" {
		value = "Not available"
	}

	boxLine(paint(bold, label+":"))

	for _, line := range wrap(value, width-4) {
		boxLine("  " + line)
	}
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
