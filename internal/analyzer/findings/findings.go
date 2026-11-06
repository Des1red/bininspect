package findings

import (
	"fmt"
	"sort"
	"strings"

	"bininspect/internal/analyzer/shared"
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

func Analyze(
	calls []models.FunctionCall,
	security models.SecurityAnalysis,
	relations ...models.StackRelation,
) []models.Finding {
	var findings []models.Finding

	imports := models.Knowledge.Dynamic + "\n" +
		models.Knowledge.Symbols

	names := make([]string, 0, len(riskyFunctions))

	for name := range riskyFunctions {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		risk := riskyFunctions[name]

		var evidence []string
		confidence := "low"

		for _, call := range calls {
			if strings.TrimLeft(call.Name, "_") != name {
				continue
			}

			evidence = append(evidence, fmt.Sprintf(
				"Call at 0x%s: %s",
				call.Address,
				call.Instruction,
			))

			confidence = "high"
		}

		if symbolMentioned(imports, name) {
			evidence = append(
				evidence,
				"Import/symbol reference: "+name,
			)
		}

		if len(evidence) == 0 {
			continue
		}

		for _, relation := range relations {
			if relation.API != name {
				continue
			}

			evidence = append(evidence, fmt.Sprintf(
				"Heuristic stack relationship in %s:\n"+
					"Destination: %s\n"+
					"Source: %s\n"+
					"Checked location: %s\n"+
					"Separation: %d bytes\n"+
					"Compared value: %s\n"+
					"Branch: %s at 0x%s\n"+
					"Initially zero: %t",
				relation.Function,
				relation.InputReference,
				relation.SourceReference,
				relation.CheckedReference,
				relation.Distance,
				relation.ComparedValue,
				relation.BranchCondition,
				relation.BranchSite,
				relation.InitializedZero,
			))
		}

		findings = append(findings, models.Finding{
			ID:             "API-" + name,
			Category:       "Potentially unsafe API",
			Severity:       risk.Severity,
			Confidence:     confidence,
			Description:    risk.Description,
			Evidence:       strings.Join(evidence, "\n"),
			Recommendation: risk.Recommendation,
		})
	}

	if security.NX.Status == "disabled" {
		findings = append(findings, models.Finding{
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
		findings = append(findings, models.Finding{
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
	for _, line := range shared.Lines(data) {
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
