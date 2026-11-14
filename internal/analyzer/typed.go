package analyzer

import (
	"debug/elf"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/dataflow"
	"bininspect/internal/analyzer/findings"
	"bininspect/internal/analyzer/functions"
	"bininspect/internal/analyzer/security"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

type Structure struct {
	Programs           int
	Sections           int
	Symbols            int
	DynamicSymbols     int
	Relocations        int
	DynamicRelocations int
	Dependencies       int
}

type AssemblySummary struct {
	CandidateInstructions int
	Calls                 int
	Jumps                 int
	ConditionalBranches   int
	Returns               int
	SystemInstructions    int
	Traps                 int
	SkippedBytes          uint64
	SkippedDataBytes      uint64
}

type Result struct {
	Info        binary.Info
	ELFType     elf.Type
	Structure   Structure
	Assembly    AssemblySummary
	Graphs      []cfg.Graph
	Diagnostics []decoder.Diagnostic
	Warnings    []string
	Functions   []functions.Function
	DataFlow    dataflow.Result
	Security    security.Result
	Findings    []findings.Finding
}
