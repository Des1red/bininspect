package analyzer

import (
	"errors"
	"fmt"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/dataflow"
	"bininspect/internal/analyzer/findings"
	"bininspect/internal/analyzer/functions"
	"bininspect/internal/analyzer/security"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

// AnalyzeELF is the new typed analysis entry point.
// It does not depend on models.Knowledge or external tools.
func AnalyzeELF(
	parsed *binary.ELFResult,
	decoded decoder.Result,
) (Result, error) {
	var result Result

	if parsed == nil {
		return result, errors.New(
			"nil ELF analysis input",
		)
	}

	if (parsed.Image == nil) == (parsed.Object == nil) {
		return result, errors.New(
			"ELF input requires exactly one image or object",
		)
	}

	if parsed.Info.Format != binary.FormatELF {
		return result, fmt.Errorf(
			"expected ELF, got %s",
			parsed.Info.Format,
		)
	}

	graphs, err := cfg.BuildWithLeaders(
		decoded,
		functions.Leaders(parsed, decoded),
	)
	if err != nil {
		return result, err
	}

	result = Result{
		Info:    parsed.Info,
		ELFType: parsed.Header.Type,
		Structure: Structure{
			Programs:           len(parsed.Programs),
			Sections:           len(parsed.Sections),
			Symbols:            len(parsed.Metadata.Symbols),
			DynamicSymbols:     len(parsed.DynamicMetadata.Symbols),
			Relocations:        len(parsed.Metadata.Relocations),
			DynamicRelocations: len(parsed.DynamicMetadata.Relocations),
			Dependencies:       len(parsed.Dynamic.Needed),
		},
		Graphs: graphs,
		Diagnostics: append(
			[]decoder.Diagnostic(nil),
			decoded.Diagnostics...,
		),
		Warnings: append(
			[]string(nil),
			parsed.Validation.Warnings...,
		),
	}

	result.Warnings = append(
		result.Warnings,
		parsed.DynamicMetadata.Warnings...,
	)
	result.Warnings = append(
		result.Warnings,
		parsed.Versions.Warnings...,
	)

	result.Assembly.SkippedBytes = decoded.SkippedBytes
	result.Assembly.SkippedDataBytes = decoded.SkippedDataBytes

	for _, section := range decoded.Sections {
		for _, inst := range section.Instructions {
			result.Assembly.CandidateInstructions++

			switch inst.Flow {
			case decoder.FlowCall:
				result.Assembly.Calls++

			case decoder.FlowJump:
				result.Assembly.Jumps++

			case decoder.FlowConditional:
				result.Assembly.ConditionalBranches++

			case decoder.FlowReturn:
				result.Assembly.Returns++

			case decoder.FlowSystem:
				result.Assembly.SystemInstructions++

			case decoder.FlowTrap:
				result.Assembly.Traps++
			}
		}
	}

	result.Functions = functions.Recover(
		parsed,
		result.Graphs,
	)
	result.DataFlow = dataflow.Analyze(
		parsed,
		result.Graphs,
		result.Functions,
	)
	result.Security = security.Analyze(parsed)
	result.Warnings = append(
		result.Warnings,
		result.DataFlow.Warnings...,
	)
	result.Findings = findings.Evaluate(
		parsed,
		result.Graphs,
		result.DataFlow,
		result.Security,
	)

	return result, nil
}
