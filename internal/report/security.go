package report

import (
	"fmt"
	"strings"

	"bininspect/internal/models"
)

func Security(r models.ResultsModel) {
	fmt.Println("┌" + strings.Repeat("─", width) + "┐")
	boxLine(paint(bold+cyan, "06  SECURITY PROTECTIONS"))
	fmt.Println("├" + strings.Repeat("─", width) + "┤")

	securityRow("NX", r.Security.NX)
	securityRow("PIE", r.Security.PIE)
	securityRow("RELRO", r.Security.RELRO)
	securityRow("Stack Canary", r.Security.Canary)
	securityRow("ASLR", r.Security.ASLR)
	securityRow("CFG", r.Security.CFG)

	fmt.Println("└" + strings.Repeat("─", width) + "┘")
}

func securityRow(name string, check models.SecurityCheck) {
	status := check.Status
	if status == "" {
		status = "unknown"
	}

	value := fmt.Sprintf("%-20s %s", name, strings.ToUpper(status))
	boxLine(paint(statusColor(status), value))

	if check.Evidence != "" {
		// Evidence is shortened rather than dumping raw headers.
		for _, line := range wrap(
			"Evidence: "+short(check.Evidence, 115),
			width-4,
		) {
			boxLine(paint(gray, "  "+line))
		}
	}
}
