package report

import (
	"regexp"
	"strings"
)

var summaryTokens = regexp.MustCompile(
	`(?i)\b(?:critical|high|disabled|` +
		`unknown|potential|possible|partial|` +
		`unavailable|unresolved|heuristic|` +
		`cannot|uncertain|` +
		`ELF32|ELF64|ELF|PE|Mach-O|` +
		`Intel 80386|x86-64|` +
		`NX|PIE|RELRO|ASLR|CFG|` +
		`enabled|detected)\b|` +
		`\b\d+\s+(?:sections?|segments?|symbols?|` +
		`relocations?|linked libraries|parsed instructions?|` +
		`discovered functions?|calls?|branches?|returns?|` +
		`findings?|bytes|stack allocation operations?)\b|` +
		`\b0x[0-9a-fA-F]+\b|` +
		`\b[a-zA-Z_][a-zA-Z_0-9]*\(\)`,
)

func summaryBox(title string, rows ...string) {
	emitln("┌" + strings.Repeat("─", width) + "┐")
	boxLine(paint(bold+cyan, title))
	emitln("├" + strings.Repeat("─", width) + "┤")

	for _, row := range rows {
		for _, line := range wrap(row, width-2) {
			boxLine(colorSummary(line, nil))
		}
	}

	emitln("└" + strings.Repeat("─", width) + "┘")
}

func colorSummary(
	line string,
	riskyAPIs map[string]bool,
) string {
	if !colors {
		return line
	}

	return summaryTokens.ReplaceAllStringFunc(
		line,
		func(token string) string {
			lower := strings.ToLower(token)

			// Unsafe API names, based on actual findings.
			if strings.HasSuffix(lower, "()") {
				name := strings.TrimSuffix(lower, "()")

				if riskyAPIs[name] {
					return paint(bold+red, token)
				}

				return token
			}

			switch lower {
			case "critical", "high", "disabled":
				return paint(bold+red, token)

			case "unknown", "potential", "possible",
				"partial", "unavailable", "unresolved",
				"heuristic", "cannot", "uncertain":
				return paint(yellow, token)

			case "enabled", "detected":
				return paint(green, token)

			default:
				// Architecture, protection names,
				// numeric statistics and addresses.
				return paint(bold+blue, token)
			}
		},
	)
}
