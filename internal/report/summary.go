package report

import (
	"fmt"
	"strings"

	"bininspect/internal/models"
)

func Summary(r models.ResultsModel) {
	paragraphs := []string{
		summaryBinary(r),
		summaryFindings(r),
		summaryFlow(r),
		summaryProtections(r.Security),
		summaryCoverage(r),
		summaryLimitations(),
	}

	var rows []string

	for _, paragraph := range paragraphs {
		if paragraph == "" {
			continue
		}

		if len(rows) > 0 {
			rows = append(rows, "")
		}

		rows = append(rows, paragraph)
	}

	summaryBox("08  ANALYSIS SUMMARY", r, rows...)
}

func summaryBinary(r models.ResultsModel) string {
	id := r.Identity
	a := r.Assembly
	s := r.Structure

	format := id.Format
	if format == "" {
		format = "unknown"
	}

	var identity []string

	if id.Class != "" {
		identity = append(identity, id.Class)
	}

	if id.Architecture != "" {
		identity = append(identity, id.Architecture)
	}

	description := format + " binary"

	if len(identity) > 0 {
		description += " (" + strings.Join(identity, ", ") + ")"
	}

	return fmt.Sprintf(
		"BinInspect analyzed this %s and identified %s, "+
			"%s, %s, %s and %s. "+
			"The disassembly contains %s across "+
			"%s, including %s, %s and %s. "+
			"The analyzer also recorded %s.",
		description,
		countLabel(len(s.Sections), "section", "sections"),
		countLabel(len(s.Segments), "segment", "segments"),
		countLabel(len(s.Symbols), "symbol", "symbols"),
		countLabel(s.Relocations, "relocation", "relocations"),
		countLabel(len(s.Libraries), "linked library", "linked libraries"),
		countLabel(len(a.Instructions), "parsed instruction", "parsed instructions"),
		countLabel(len(r.FunctionDefinitions), "discovered function", "discovered functions"),
		countLabel(a.Calls, "call", "calls"),
		countLabel(a.Branches, "branch", "branches"),
		countLabel(a.Returns, "return", "returns"),
		countLabel(len(a.StackAllocations), "stack allocation operation", "stack allocation operations"),
	)
}

func summaryFindings(r models.ResultsModel) string {
	if len(r.Findings) == 0 {
		return "The current detection rules produced no security findings. " +
			"This does not establish that the binary is secure."
	}

	counts := make(map[string]int)

	var apis []string
	var identifiers []string

	for _, finding := range r.Findings {
		severity := strings.ToLower(
			strings.TrimSpace(finding.Severity),
		)

		counts[severity]++

		if strings.HasPrefix(finding.ID, "API-") {
			apis = append(
				apis,
				strings.TrimPrefix(finding.ID, "API-")+"()",
			)
		}

		if finding.ID != "" {
			identifiers = append(
				identifiers,
				fmt.Sprintf(
					"%s (%s)",
					finding.ID,
					severity,
				),
			)
		}
	}

	var severities []string

	for _, severity := range []string{
		"critical", "high", "medium", "low", "info",
	} {
		if count := counts[severity]; count > 0 {
			severities = append(
				severities,
				fmt.Sprintf("%d %s", count, severity),
			)
		}
	}

	text := fmt.Sprintf(
		"The security analysis produced %s",
		countLabel(len(r.Findings), "finding", "findings"),
	)

	if len(severities) > 0 {
		text += " (" + strings.Join(severities, ", ") + ")"
	}

	text += "."

	if len(apis) == 1 {
		text += " A potentially unsafe API reference was identified: " +
			apis[0] +
			". Its presence indicates code requiring review, " +
			"but does not independently establish unsafe use."

	} else if len(apis) > 1 {
		text += " Potentially unsafe API references include " +
			strings.Join(apis, ", ") +
			". Their presence indicates code requiring review, " +
			"but does not independently establish unsafe use."
	}

	if counts["critical"] > 0 || counts["high"] > 0 {
		text += " Findings classified as high or critical " +
			"should be prioritized for review."
	}

	if fullReport && len(identifiers) > 0 {
		text += " Recorded findings: " +
			strings.Join(identifiers, "; ") + "."
	}

	return text
}

func summaryFlow(r models.ResultsModel) string {
	a := r.Assembly

	text := fmt.Sprintf(
		"Argument tracing modeled %s.",
		countLabel(
			len(a.CallFlows),
			"recognized API call site",
			"recognized API call sites",
		),
	)

	if len(a.StackRelations) == 0 {
		return text +
			" No candidate stack-memory overwrite relationships " +
			"were established by the current analysis."
	}

	text += fmt.Sprintf(
		" The analyzer identified %s.",
		countLabel(
			len(a.StackRelations),
			"potential stack-memory relationship",
			"potential stack-memory relationships",
		),
	)

	limit := len(a.StackRelations)

	if !fullReport && limit > 2 {
		limit = 2
	}

	for _, relation := range a.StackRelations[:limit] {
		function := relation.Function

		if function == "" {
			function = "an unidentified function"
		}

		description := fmt.Sprintf(
			" In %s, a call to %s() at 0x%s uses a stack "+
				"destination at %s. A subsequently checked "+
				"location at %s is %d bytes away.",
			function,
			relation.API,
			relation.CallSite,
			relation.InputReference,
			relation.CheckedReference,
			relation.Distance,
		)

		if relation.SourceReference != "" &&
			relation.SourceReference != "unknown" {

			description += fmt.Sprintf(
				" The recorded source expression is %s.",
				relation.SourceReference,
			)
		}

		if relation.ComparedValue != "" &&
			relation.ComparedValue != "unknown" {

			description += fmt.Sprintf(
				" The checked value is compared against %s.",
				relation.ComparedValue,
			)
		}

		if relation.BranchCondition != "" {
			description += fmt.Sprintf(
				" The associated branch is %s at 0x%s.",
				relation.BranchCondition,
				relation.BranchSite,
			)
		}

		if relation.InitializedZero {
			description += " The checked stack location was " +
				"observed being initialized to zero."
		}

		text += description
	}

	if !fullReport && len(a.StackRelations) > limit {
		remaining := len(a.StackRelations) - limit

		text += fmt.Sprintf(
			" %s documented in the saved report.",
			countLabel(
				remaining,
				"additional relationship is",
				"additional relationships are",
			),
		)
	}

	text += " These relationships identify memory locations " +
		"requiring further review; their separation does not " +
		"independently establish destination buffer capacity."

	return text
}

func summaryProtections(s models.SecurityAnalysis) string {
	checks := []struct {
		name  string
		check models.SecurityCheck
	}{
		{"NX", s.NX},
		{"PIE", s.PIE},
		{"RELRO", s.RELRO},
		{"Stack Canary", s.Canary},
		{"ASLR", s.ASLR},
		{"CFG", s.CFG},
	}

	var statuses []string
	var disabled []string
	var partial []string
	var unknown []string

	for _, item := range checks {
		status := strings.ToLower(
			strings.TrimSpace(item.check.Status),
		)

		if status == "" {
			status = "unknown"
		}

		statuses = append(
			statuses,
			fmt.Sprintf("%s: %s", item.name, status),
		)

		switch status {
		case "disabled":
			disabled = append(disabled, item.name)

		case "partial":
			partial = append(partial, item.name)

		case "unknown":
			unknown = append(unknown, item.name)
		}
	}

	text := "The security protection checks report " +
		strings.Join(statuses, "; ") + "."

	if len(disabled) > 0 {
		text += " Protections explicitly reported as disabled: " +
			strings.Join(disabled, ", ") + "."
	} else {
		text += " No protections were explicitly classified as disabled " +
			"by the current checks."
	}

	if len(partial) > 0 {
		text += " Partially implemented protections: " +
			strings.Join(partial, ", ") + "."
	}

	if len(unknown) == 1 {
		text += " The status of " + unknown[0] +
			" remains unknown; this must not be interpreted " +
			"as either enabled or disabled."

	} else if len(unknown) > 1 {
		text += " The statuses of " +
			strings.Join(unknown, ", ") +
			" remain unknown; these must not be interpreted " +
			"as either enabled or disabled."
	}

	return text
}

func summaryCoverage(r models.ResultsModel) string {
	var observations []string

	if source, exists := r.Sources["assembly"]; !exists ||
		!source.Available {

		observations = append(
			observations,
			"No disassembly dataset was available, "+
				"limiting instruction-level conclusions.",
		)
	}

	if r.Identity.Format == "ELF" && !r.Structure.DebugInfo {
		observations = append(
			observations,
			"DWARF debugging information was not identified, "+
				"so detailed source-level context may be unavailable.",
		)
	}

	return strings.Join(observations, " ")
}

func summaryLimitations() string {
	return "This report is based on static binary analysis. " +
		"Function calls, memory relationships and protection statuses " +
		"are interpreted from the collected evidence. " +
		"The data-flow tracker does not yet perform complete " +
		"control-flow or path-sensitive analysis, and cannot establish " +
		"every buffer bound, pointer alias or runtime memory effect. " +
		"Consequently, the results neither prove exploitability " +
		"nor guarantee the absence of vulnerabilities."
}

func countLabel(
	count int,
	singular string,
	plural string,
) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}

	return fmt.Sprintf("%d %s", count, plural)
}
