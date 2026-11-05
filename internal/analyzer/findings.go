package analyzer

import (
	"fmt"
	"strings"

	"bininspect/internal/models"
)

type riskyFunction struct {
	Severity       string
	Description    string
	Recommendation string
}

var riskyFunctions = map[string]riskyFunction{
	"gets": {
		Severity:       "high",
		Description:    "Reads input without enforcing destination capacity.",
		Recommendation: "Use bounded input handling such as fgets.",
	},
	"strcpy": {
		Severity:       "medium",
		Description:    "Copies strings without checking destination capacity.",
		Recommendation: "Validate lengths and destination capacity.",
	},
	"strcat": {
		Severity:       "medium",
		Description:    "Appends strings without checking destination capacity.",
		Recommendation: "Validate remaining destination capacity.",
	},
	"sprintf": {
		Severity:       "medium",
		Description:    "Unbounded formatted output may overflow a destination.",
		Recommendation: "Use snprintf with the correct buffer size.",
	},
	"scanf": {
		Severity:       "medium",
		Description:    "Some format specifiers can read unbounded input.",
		Recommendation: "Review format strings and specify field widths.",
	},
}

func Findings(
	calls []models.FunctionCall,
	security models.SecurityAnalysis,
) []models.Finding {
	var findings []models.Finding
	seen := make(map[string]bool)

	add := func(f models.Finding) {
		key := f.Category + ":" + f.Evidence

		if seen[key] {
			return
		}

		seen[key] = true
		findings = append(findings, f)
	}

	for _, call := range calls {
		name := strings.TrimLeft(call.Name, "_")

		risk, exists := riskyFunctions[name]
		if !exists {
			continue
		}

		add(models.Finding{
			ID:         fmt.Sprintf("FUNC-%s-%s", name, call.Address),
			Category:   "Unsafe function call",
			Severity:   risk.Severity,
			Confidence: "high",
			Description: fmt.Sprintf(
				"Call to %s: %s", name, risk.Description,
			),
			Evidence: fmt.Sprintf(
				"0x%s: %s", call.Address, call.Instruction,
			),
			Recommendation: risk.Recommendation,
		})
	}

	// Imported symbols may be visible even when calls cannot
	// be recovered from the disassembly.
	importSources := models.Knowledge.Dynamic + "\n" +
		models.Knowledge.Symbols

	for name, risk := range riskyFunctions {
		if !symbolMentioned(importSources, name) {
			continue
		}

		add(models.Finding{
			ID:             "IMPORT-" + name,
			Category:       "Potentially unsafe imported function",
			Severity:       risk.Severity,
			Confidence:     "low",
			Description:    risk.Description,
			Evidence:       "Symbol/import reference: " + name,
			Recommendation: risk.Recommendation,
		})
	}

	if security.NX.Status == "disabled" {
		add(models.Finding{
			ID:             "SEC-NX",
			Category:       "Executable stack",
			Severity:       "medium",
			Confidence:     "high",
			Description:    "The ELF stack is marked executable.",
			Evidence:       security.NX.Evidence,
			Recommendation: "Review executable-stack requirements and enable NX.",
		})
	}

	if security.PIE.Status == "disabled" {
		add(models.Finding{
			ID:             "SEC-PIE",
			Category:       "Non-PIE executable",
			Severity:       "low",
			Confidence:     "high",
			Description:    "The executable is not position-independent.",
			Evidence:       security.PIE.Evidence,
			Recommendation: "Consider building with PIE support.",
		})
	}

	return findings
}

func symbolMentioned(data, name string) bool {
	for _, line := range lines(data) {
		for _, token := range strings.FieldsFunc(line, func(r rune) bool {
			return !(r >= 'a' && r <= 'z') &&
				!(r >= 'A' && r <= 'Z') &&
				!(r >= '0' && r <= '9') &&
				r != '_'
		}) {
			if strings.TrimLeft(token, "_") == name {
				return true
			}
		}
	}

	return false
}
