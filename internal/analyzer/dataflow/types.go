package dataflow

import "fmt"

// Value is an abstract fact, not an observed runtime value.
// Empty Kind means that the value is unknown.
type Value struct {
	Kind        string // "constant" or "stack-address"
	Number      int64
	StackOffset int64 // relative to the entry stack pointer
}

func (v Value) String() string {
	switch v.Kind {
	case "constant":
		return fmt.Sprintf("%#x", v.Number)
	case "stack-address":
		return fmt.Sprintf("entry-SP%+d", v.StackOffset)
	default:
		return "unknown"
	}
}

type Argument struct {
	Position int
	Location string
	Value    Value
}

type CallTrace struct {
	Function  string
	Section   int
	Address   uint64
	Target    string
	Indirect  bool
	Arguments []Argument
}

// StackUse is the greatest negative stack-pointer displacement seen
// on a modeled path. It is NOT a proven local-buffer size.
type StackUse struct {
	Function      string
	Section       int
	Entry         uint64
	MaxDepthBytes int64
	Partial       bool // Some reachable SP values were unknown.
}

type Result struct {
	Supported bool
	Calls     []CallTrace
	Stack     []StackUse
	Warnings  []string
}
