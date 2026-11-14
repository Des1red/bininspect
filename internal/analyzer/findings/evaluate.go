package findings

import (
	"debug/elf"
	"fmt"
	"sort"
	"strings"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/dataflow"
	"bininspect/internal/analyzer/resolve"
	"bininspect/internal/analyzer/security"
	"bininspect/internal/binary"
)

// Finding records an observed ELF property or an API reference
// requiring review. It is not proof of exploitability.
type Finding struct {
	ID             string
	Title          string
	Category       string
	Severity       string
	Confidence     string
	Description    string
	Evidence       []string
	Recommendation string
	Section        int
	Address        uint64
	HasAddress     bool
}

type apiRisk struct {
	Severity       string
	Description    string
	Recommendation string
}

var riskyAPIs = map[string]apiRisk{
	"gets": {
		"high",
		"Unbounded input function referenced; a destination buffer may overflow.",
		"Remove gets; use a bounded input API and check its return value.",
	},
	"strcpy": {
		"medium",
		"String copy does not check the destination capacity.",
		"Validate source length and destination capacity.",
	},
	"strcat": {
		"medium",
		"String append does not check remaining destination capacity.",
		"Check remaining space before concatenation.",
	},
	"sprintf": {
		"medium",
		"Formatted output does not enforce destination capacity.",
		"Use snprintf with the actual destination size.",
	},
	"vsprintf": {
		"medium",
		"Formatted output does not enforce destination capacity.",
		"Use vsnprintf with the actual destination size.",
	},
	"scanf": {
		"low",
		"Unbounded %s or %[ conversions can overflow character buffers; format not evaluated.",
		"Review the format and specify field widths.",
	},
	"sscanf": {
		"low",
		"Unbounded %s or %[ conversions can overflow character buffers; format not evaluated.",
		"Review the format and specify field widths.",
	},
	"fscanf": {
		"low",
		"Unbounded %s or %[ conversions can overflow character buffers; format not evaluated.",
		"Review the format and specify field widths.",
	},
}

func apiName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.SplitN(name, "@", 2)[0]
	return strings.TrimPrefix(name, "__isoc99_")
}

func functionAddresses(
	parsed *binary.ELFResult,
) map[uint64]string {
	result := make(map[uint64]string)

	if parsed == nil || parsed.Object != nil {
		return result
	}

	for _, symbols := range [][]binary.ELFSymbol{
		parsed.Metadata.Symbols,
		parsed.DynamicMetadata.Symbols,
	} {
		for _, sym := range symbols {
			if sym.Type != elf.STT_FUNC ||
				sym.SectionIndex == uint32(elf.SHN_UNDEF) ||
				sym.Name == "" {
				continue
			}

			if _, exists := result[sym.Value]; !exists {
				result[sym.Value] = sym.Name
			}
		}
	}

	return result
}

// Evaluate combines named call sites, abstract argument values,
// and observed ELF hardening indicators.
func Evaluate(
	parsed *binary.ELFResult,
	graphs []cfg.Graph,
	flow dataflow.Result,
	hardening security.Result,
) []Finding {
	if parsed == nil {
		return nil
	}

	var result []Finding
	names := functionAddresses(parsed)
	for address, name := range resolve.PLTTargets(parsed, graphs) {
		if names[address] == "" {
			names[address] = name
		}
	}

	type location struct {
		section int
		address uint64
	}

	traces := make(map[location]dataflow.CallTrace)

	for _, trace := range flow.Calls {
		key := location{trace.Section, trace.Address}

		if _, exists := traces[key]; !exists {
			traces[key] = trace
		}
	}

	seenCalls := make(map[location]bool)
	observedAPI := make(map[string]bool)

	addCall := func(
		section int,
		address uint64,
		target string,
		trace dataflow.CallTrace,
	) {
		name := apiName(target)
		risk, known := riskyAPIs[name]
		if !known {
			return
		}

		observedAPI[name] = true

		evidence := []string{
			fmt.Sprintf(
				"Named call reference: %s at section %d, %#x",
				target, section, address,
			),
		}

		if trace.Function != "" {
			evidence = append(
				evidence,
				"Recovered function: "+trace.Function,
			)
		}

		for _, arg := range trace.Arguments {
			if arg.Position > 3 {
				break
			}

			if arg.Value.Kind != "" {
				evidence = append(evidence, fmt.Sprintf(
					"Modeled argument %d (%s): %s",
					arg.Position,
					arg.Location,
					arg.Value.String(),
				))
			}
		}

		result = append(result, Finding{
			ID: fmt.Sprintf(
				"API-%s-%d-%x", name, section, address,
			),
			Title:      name + "() call requires review",
			Category:   "Potentially unsafe API",
			Severity:   risk.Severity,
			Confidence: "high",
			Description: risk.Description +
				" A named call reference is evidence of use, " +
				"not proof of memory corruption.",
			Evidence:       evidence,
			Recommendation: risk.Recommendation,
			Section:        section,
			Address:        address,
			HasAddress:     true,
		})
	}

	// Primary source: actual CFG call sites.
	for _, graph := range graphs {
		for _, call := range graph.Calls {
			key := location{graph.Section, call.Address}

			if seenCalls[key] {
				continue
			}
			seenCalls[key] = true

			trace := traces[key]
			target := call.Symbol

			if target == "" &&
				call.HasTarget &&
				!call.Indirect {
				target = names[call.Target]
			}

			if target == "" && trace.Target != "unresolved" {
				target = trace.Target
			}

			addCall(graph.Section, call.Address, target, trace)
		}
	}

	// Also accept a typed call trace supplied without a CFG call.
	for _, trace := range flow.Calls {
		key := location{trace.Section, trace.Address}

		if seenCalls[key] {
			continue
		}
		seenCalls[key] = true

		addCall(
			trace.Section,
			trace.Address,
			trace.Target,
			trace,
		)
	}

	// Undefined symbols indicate imports, not proven calls.
	imported := make(map[string]bool)

	for _, symbols := range [][]binary.ELFSymbol{
		parsed.Metadata.Symbols,
		parsed.DynamicMetadata.Symbols,
	} {
		for _, sym := range symbols {
			if sym.SectionIndex != uint32(elf.SHN_UNDEF) ||
				sym.Type != elf.STT_FUNC {
				continue
			}

			name := apiName(sym.Name)

			if _, known := riskyAPIs[name]; known {
				imported[name] = true
			}
		}
	}

	for name := range imported {
		if observedAPI[name] {
			continue
		}

		result = append(result, Finding{
			ID:         "IMPORT-" + name,
			Title:      name + "() import requires review",
			Category:   "Unconfirmed risky import",
			Severity:   "info",
			Confidence: "low",
			Description: "An undefined symbol refers to a " +
				"potentially unsafe API, but no matching " +
				"call site was resolved.",
			Evidence: []string{
				"Undefined ELF function symbol: " + name,
			},
			Recommendation: "Determine whether reachable " +
				"code uses this import before evaluating safety.",
		})
	}

	// Only raise hardening findings for observed ELF properties.
	// ET_REL has no final linked hardening to evaluate.
	if parsed.Header.Type == elf.ET_EXEC ||
		parsed.Header.Type == elf.ET_DYN {

		addProtection := func(
			id, title, severity, description,
			recommendation string,
			check security.Check,
		) {
			evidence := append(
				[]string(nil),
				check.Evidence...,
			)

			if check.Note != "" {
				evidence = append(
					evidence,
					"Assessment: "+check.Note,
				)
			}

			result = append(result, Finding{
				ID:             id,
				Title:          title,
				Category:       "ELF hardening",
				Severity:       severity,
				Confidence:     "high",
				Description:    description,
				Evidence:       evidence,
				Recommendation: recommendation,
			})
		}

		if hardening.NX.Status == "disabled" {
			addProtection(
				"SEC-EXECSTACK",
				"Executable stack requested",
				"medium",
				"PT_GNU_STACK requests an executable stack.",
				"Disable executable-stack permissions unless required.",
				hardening.NX,
			)
		}

		if hardening.RWX.Status == "present" {
			addProtection(
				"SEC-RWX",
				"Writable and executable load segment",
				"high",
				"At least one PT_LOAD is both writable and executable.",
				"Separate writable and executable mappings.",
				hardening.RWX,
			)
		}

		if parsed.Header.Type == elf.ET_EXEC &&
			hardening.PIE.Status == "disabled" {
			addProtection(
				"SEC-NONPIE",
				"Non-PIE executable",
				"low",
				"ET_EXEC limits executable text randomization.",
				"Build the executable as PIE where supported.",
				hardening.PIE,
			)
		}

		switch hardening.RELRO.Status {
		case "disabled":
			addProtection(
				"SEC-RELRO",
				"RELRO not requested",
				"low",
				"No effective PT_GNU_RELRO was observed.",
				"Link with RELRO and immediate binding where applicable.",
				hardening.RELRO,
			)

		case "partial":
			addProtection(
				"SEC-PARTIAL-RELRO",
				"Partial RELRO",
				"info",
				"RELRO is requested but immediate binding was not observed.",
				"Consider full RELRO with immediate binding.",
				hardening.RELRO,
			)
		}
	}

	rank := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}

	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]

		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] > rank[b.Severity]
		}

		return a.ID < b.ID
	})

	return result
}
