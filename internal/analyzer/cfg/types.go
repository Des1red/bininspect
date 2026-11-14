package cfg

import "bininspect/internal/decoder"

// A graph represents one executable section or mapped region.
// ET_REL section-relative addresses must not be merged merely
// because their numeric addresses are equal.
type Graph struct {
	Section int
	Name    string
	Blocks  []Block
	Edges   []Edge
	Calls   []CallSite
}

type Block struct {
	Start        uint64
	End          uint64 // Exclusive
	Instructions []decoder.Instruction
}

type EdgeKind string

const (
	EdgeFallthrough      EdgeKind = "fallthrough"
	EdgeBranch           EdgeKind = "branch"
	EdgeConditional      EdgeKind = "conditional"
	EdgeConditionalFalse EdgeKind = "conditional-false"
	EdgeIndirect         EdgeKind = "indirect"
)

// To is -1 for unresolved or out-of-section targets.
type Edge struct {
	From   int
	To     int
	Target uint64
	Kind   EdgeKind
	Symbol string
}

type CallSite struct {
	Address   uint64
	Target    uint64
	HasTarget bool
	Indirect  bool
	Symbol    string
}
