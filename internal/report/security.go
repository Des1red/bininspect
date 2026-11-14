package report

import (
	"fmt"
	"strings"

	"bininspect/internal/analyzer"
	"bininspect/internal/analyzer/security"
)

func Security(r analyzer.Result) {
	emitln("┌" + strings.Repeat("─", width) + "┐")
	boxLine(paint(bold+cyan, "07  SECURITY PROTECTIONS"))
	emitln("├" + strings.Repeat("─", width) + "┤")

	checks := []struct {
		Name  string
		Check security.Check
	}{
		{"NX / Stack", r.Security.NX},
		{"PIE", r.Security.PIE},
		{"RELRO", r.Security.RELRO},
		{"Stack Canary", r.Security.Canary},
		{"FORTIFY", r.Security.Fortify},
		{"ASLR", r.Security.ASLR},
		{"RWX Segments", r.Security.RWX},
	}

	for i, item := range checks {
		if i > 0 {
			boxLine("")
		}

		color := statusColor(item.Check.Status)

		if item.Name == "RWX Segments" &&
			item.Check.Status == "present" {
			color = red
		}

		status := strings.ToUpper(item.Check.Status)

		boxLine(fmt.Sprintf(
			"%-20s %s",
			item.Name,
			paint(color, status),
		))

		if item.Check.Note != "" {
			for _, line := range wrap(
				"  "+item.Check.Note,
				width-3,
			) {
				boxLine(paint(gray, line))
			}
		}

		for j, evidence := range item.Check.Evidence {
			if !fullReport && j >= 2 {
				boxLine(fmt.Sprintf(
					"  ... %d more evidence entries",
					len(item.Check.Evidence)-j,
				))
				break
			}

			for _, line := range wrap(
				"  Evidence: "+evidence,
				width-3,
			) {
				boxLine(line)
			}
		}
	}

	emitln("└" + strings.Repeat("─", width) + "┘")
}
