package security

import (
	"strings"

	"bininspect/internal/analyzer/shared"
	"bininspect/internal/models"
)

func Analyze() models.SecurityAnalysis {
	unknown := models.SecurityCheck{
		Status: "unknown",
	}

	result := models.SecurityAnalysis{
		NX:     unknown,
		PIE:    unknown,
		RELRO:  unknown,
		Canary: unknown,
		ASLR:   unknown,
		CFG:    unknown,
	}

	k := models.Knowledge

	switch models.Scope.Format {
	case "ELF":
		elfSecurity(&result)

	case "PE":
		peSecurity(&result)

	case "Mach-O":
		machoSecurity(&result)
	}

	if strings.Contains(k.Symbols, "__stack_chk_fail") ||
		strings.Contains(k.Assembly, "__stack_chk_fail") {

		result.Canary = models.SecurityCheck{
			Status:   "detected",
			Evidence: "__stack_chk_fail reference",
		}
	}

	return result
}

func elfSecurity(result *models.SecurityAnalysis) {
	k := models.Knowledge

	for _, line := range shared.Lines(k.Programs) {
		fields := strings.Fields(line)

		if len(fields) < 3 || fields[0] != "GNU_STACK" {
			continue
		}

		flags := strings.Join(fields[1:len(fields)-1], "")

		if strings.Contains(flags, "E") {
			result.NX = models.SecurityCheck{
				Status:   "disabled",
				Evidence: line,
			}
		} else {
			result.NX = models.SecurityCheck{
				Status:   "enabled",
				Evidence: line,
			}
		}
	}

	switch {
	case strings.Contains(k.ELF, "Type:") &&
		strings.Contains(shared.Field(k.ELF, "Type:"), "EXEC"):
		result.PIE = models.SecurityCheck{
			Status:   "disabled",
			Evidence: shared.Field(k.ELF, "Type:"),
		}

	case strings.Contains(shared.Field(k.ELF, "Type:"), "DYN"):
		result.PIE = models.SecurityCheck{
			Status:   "possible",
			Evidence: "ET_DYN may indicate PIE or a shared object",
		}
	}

	if strings.Contains(k.Programs, "GNU_RELRO") {
		result.RELRO = models.SecurityCheck{
			Status:   "partial",
			Evidence: "GNU_RELRO segment",
		}

		if strings.Contains(k.Dynamic, "BIND_NOW") ||
			strings.Contains(k.Dynamic, "FLAGS") &&
				strings.Contains(k.Dynamic, "NOW") {

			result.RELRO.Status = "full"
			result.RELRO.Evidence = "GNU_RELRO and immediate binding"
		}
	}
}

func peSecurity(result *models.SecurityAnalysis) {
	data := models.Knowledge.Dynamic

	flags := ""
	for _, line := range shared.Lines(data) {
		if strings.Contains(line, "DllCharacteristics") {
			flags += line + "\n"
		}
		if strings.Contains(line, "DYNAMIC_BASE") ||
			strings.Contains(line, "NX_COMPAT") ||
			strings.Contains(line, "GUARD_CF") {
			flags += line + "\n"
		}
	}

	if strings.Contains(flags, "NX_COMPAT") {
		result.NX = models.SecurityCheck{
			Status:   "enabled",
			Evidence: "NX_COMPAT",
		}
	}

	if strings.Contains(flags, "DYNAMIC_BASE") {
		result.ASLR = models.SecurityCheck{
			Status:   "compatible",
			Evidence: "DYNAMIC_BASE",
		}
	}

	if strings.Contains(flags, "GUARD_CF") {
		result.CFG = models.SecurityCheck{
			Status:   "indicated",
			Evidence: "GUARD_CF",
		}
	}
}

func machoSecurity(result *models.SecurityAnalysis) {
	data := models.Knowledge.Security

	if strings.Contains(data, "PIE flag: true") {
		result.PIE = models.SecurityCheck{
			Status:   "enabled",
			Evidence: "Mach-O PIE flag",
		}
	}

	if strings.Contains(data, "Allow stack execution flag: true") {
		result.NX = models.SecurityCheck{
			Status:   "stack-execution-requested",
			Evidence: "Mach-O allow-stack-execution flag",
		}
	}
}
