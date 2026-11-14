package dataflow

import (
	"testing"

	"bininspect/internal/analyzer/cfg"
	"bininspect/internal/analyzer/functions"
	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func reg(name string) decoder.Operand {
	return decoder.Operand{
		Kind:     decoder.OperandRegister,
		Register: name,
	}
}

func imm(n int64) decoder.Operand {
	return decoder.Operand{
		Kind:      decoder.OperandImmediate,
		Immediate: n,
	}
}

func mem(base string, offset int64, size uint8) decoder.Operand {
	return decoder.Operand{
		Kind: decoder.OperandMemory,
		Memory: decoder.Memory{
			Base:         base,
			Displacement: offset,
			SizeBytes:    size,
		},
	}
}

func instruction(
	at uint64,
	size uint8,
	op string,
	flow decoder.FlowKind,
	args ...decoder.Operand,
) decoder.Instruction {
	return decoder.Instruction{
		Address:  at,
		Size:     size,
		Mnemonic: op,
		Flow:     flow,
		Operands: args,
	}
}

func run(
	t *testing.T,
	arch binary.Architecture,
	insts []decoder.Instruction,
) Result {
	t.Helper()

	decoded := decoder.Result{
		Sections: []decoder.DecodedSection{{
			Index:        1,
			Name:         ".text",
			Instructions: insts,
		}},
	}

	graphs, err := cfg.Build(decoded)
	if err != nil {
		t.Fatal(err)
	}

	blocks := make([]int, len(graphs[0].Blocks))
	for i := range blocks {
		blocks[i] = i
	}

	fn := functions.Function{
		Graph:   0,
		Section: 1,
		Name:    "main",
		Entry:   insts[0].Address,
		Blocks:  blocks,
	}

	return Analyze(
		&binary.ELFResult{
			Info: binary.Info{
				Architecture: arch,
			},
			Image: &binary.Image{},
		},
		graphs,
		[]functions.Function{fn},
	)
}

func TestAMD64ArgumentsAndStack(t *testing.T) {
	insts := []decoder.Instruction{
		instruction(
			0x1000, 4, "SUB", decoder.FlowNone,
			reg("RSP"), imm(0x30),
		),
		instruction(
			0x1004, 4, "LEA", decoder.FlowNone,
			reg("RDI"), mem("RSP", 0x10, 8),
		),
		instruction(
			0x1008, 5, "MOV", decoder.FlowNone,
			reg("ESI"), imm(0x20),
		),
		instruction(
			0x100d, 5, "CALL", decoder.FlowCall,
		),
		instruction(
			0x1012, 1, "RET", decoder.FlowReturn,
		),
	}

	insts[3].Relocations = []decoder.RelocationReference{{
		SymbolName: "gets",
	}}

	got := run(t, binary.ArchX8664, insts)

	if !got.Supported ||
		len(got.Calls) != 1 ||
		got.Calls[0].Target != "gets" {
		t.Fatalf("calls: %+v", got)
	}

	args := got.Calls[0].Arguments

	if args[0].Value.Kind != "stack-address" ||
		args[0].Value.StackOffset != -0x20 ||
		args[1].Value.Kind != "constant" ||
		args[1].Value.Number != 0x20 {
		t.Fatalf("args: %+v", args)
	}

	if len(got.Stack) != 1 ||
		got.Stack[0].MaxDepthBytes != 48 ||
		got.Stack[0].Partial {
		t.Fatalf("stack: %+v", got.Stack)
	}
}

func TestX8632PushArgument(t *testing.T) {
	insts := []decoder.Instruction{
		instruction(
			0x1000, 5, "PUSH", decoder.FlowNone, imm(7),
		),
		instruction(
			0x1005, 5, "CALL", decoder.FlowCall,
		),
		instruction(
			0x100a, 1, "RET", decoder.FlowReturn,
		),
	}

	got := run(t, binary.ArchX86, insts)

	if len(got.Calls) != 1 ||
		got.Calls[0].Arguments[0].Value.Number != 7 ||
		got.Calls[0].Arguments[0].Value.Kind != "constant" {
		t.Fatalf("x86 stack arg: %+v", got)
	}
}

func TestMustMergeDisagrees(t *testing.T) {
	insts := []decoder.Instruction{
		{
			Address:   0x1000,
			Size:      1,
			Flow:      decoder.FlowConditional,
			Target:    0x1005,
			HasTarget: true,
		},
		instruction(
			0x1001, 1, "MOV", decoder.FlowNone,
			reg("EDI"), imm(1),
		),
		{
			Address:   0x1002,
			Size:      1,
			Flow:      decoder.FlowJump,
			Target:    0x1006,
			HasTarget: true,
		},
		instruction(
			0x1005, 1, "MOV", decoder.FlowNone,
			reg("EDI"), imm(2),
		),
		instruction(
			0x1006, 1, "CALL", decoder.FlowCall,
		),
		instruction(
			0x1007, 1, "RET", decoder.FlowReturn,
		),
	}

	got := run(t, binary.ArchX8664, insts)

	if len(got.Calls) != 1 ||
		got.Calls[0].Arguments[0].Value.Kind != "" {
		t.Fatalf(
			"merge asserted a value across divergent paths: %+v",
			got,
		)
	}
}

func TestUnsupportedArchitecture(t *testing.T) {
	got := Analyze(
		&binary.ELFResult{
			Info: binary.Info{
				Architecture: binary.ArchARM,
			},
		},
		nil,
		nil,
	)

	if got.Supported || len(got.Warnings) == 0 {
		t.Fatalf("incorrect support status: %+v", got)
	}
}

func TestPartialRegisterDoesNotFakePointer(t *testing.T) {
	insts := []decoder.Instruction{
		instruction(
			0x1000, 1, "MOV", decoder.FlowNone,
			reg("RAX"), reg("RSP"),
		),
		instruction(
			0x1001, 1, "MOV", decoder.FlowNone,
			reg("AL"), imm(1),
		),
		instruction(
			0x1002, 1, "MOV", decoder.FlowNone,
			reg("RDI"), reg("RAX"),
		),
		instruction(
			0x1003, 1, "CALL", decoder.FlowCall,
		),
		instruction(
			0x1004, 1, "RET", decoder.FlowReturn,
		),
	}

	got := run(t, binary.ArchX8664, insts)

	if got.Calls[0].Arguments[0].Value.Kind != "" {
		t.Fatalf(
			"pointer survived partial overwrite: %+v",
			got,
		)
	}
}
