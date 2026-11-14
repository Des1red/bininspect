package decoder

import "errors"

var (
	ErrUnsupportedArchitecture = errors.New("unsupported instruction architecture")
	ErrNotExecutable           = errors.New("instruction address is not file-backed executable memory")
	ErrTruncatedInstruction    = errors.New("truncated instruction")
	ErrInvalidInstruction      = errors.New("invalid instruction")
	ErrInvalidRange            = errors.New("invalid instruction range")
)

type OperandKind uint8

const (
	OperandRegister OperandKind = iota + 1
	OperandImmediate
	OperandRelative
	OperandMemory
	OperandOpaque
)

type DecodeMode uint8

const (
	ModeDefault DecodeMode = iota
	ModeARM
	ModeThumb
)

type FlowKind uint8

const (
	FlowNone FlowKind = iota
	FlowCall
	FlowJump
	FlowConditional
	FlowReturn
	FlowSystem
	FlowTrap
)

type Memory struct {
	Segment      string
	Base         string
	Index        string
	Scale        uint8
	Displacement int64
	SizeBytes    uint8
	Addressing   string
}

type Operand struct {
	Kind      OperandKind
	Register  string
	Immediate int64
	Relative  int64
	Memory    Memory

	Target    uint64
	HasTarget bool

	// Retain the decoder representation when some operand
	// details are not expressible by the shared model.
	Text string
}

type RelocationReference struct {
	Section     int
	Offset      uint64
	WithinInsn  uint8
	Type        uint32
	SymbolIndex uint32
	SymbolName  string
	Addend      int64
	HasAddend   bool
	Encoding    string
}

type Instruction struct {
	Address  uint64
	Size     uint8
	Bytes    []byte
	Mnemonic string
	Prefixes []string
	Operands []Operand

	Flow      FlowKind
	Target    uint64
	HasTarget bool
	Indirect  bool

	AddressBits uint8
	OperandBits uint8

	Mode        DecodeMode
	Relocations []RelocationReference
}

type DecodedSection struct {
	Index        int
	Name         string
	Address      uint64
	Instructions []Instruction
}
