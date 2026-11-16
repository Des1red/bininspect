package dataflow

import (
	"testing"

	"bininspect/internal/binary"
	"bininspect/internal/decoder"
)

func TestI386AlignedStackArgument(t *testing.T) {
	reg := func(name string) decoder.Operand {
		return decoder.Operand{
			Kind:     decoder.OperandRegister,
			Register: name,
		}
	}

	imm := func(n int64) decoder.Operand {
		return decoder.Operand{
			Kind:      decoder.OperandImmediate,
			Immediate: n,
		}
	}

	mem := func(offset int64) decoder.Operand {
		return decoder.Operand{
			Kind: decoder.OperandMemory,
			Memory: decoder.Memory{
				Base:         "ESP",
				Displacement: offset,
				SizeBytes:    4,
			},
		}
	}

	// Model the stack setup and argument preparation
	// observed in the 32-bit challenge binary.
	instructions := []decoder.Instruction{
		{
			Mnemonic: "AND",
			Operands: []decoder.Operand{
				reg("ESP"),
				imm(-16),
			},
		},
		{
			Mnemonic: "SUB",
			Operands: []decoder.Operand{
				reg("ESP"),
				imm(96),
			},
		},
		{
			Mnemonic: "MOV",
			Operands: []decoder.Operand{
				mem(0x5c),
				imm(0),
			},
		},
		{
			Mnemonic: "LEA",
			Operands: []decoder.Operand{
				reg("EAX"),
				mem(0x1c),
			},
		},
		{
			Mnemonic: "MOV",
			Operands: []decoder.Operand{
				mem(0),
				reg("EAX"),
			},
		},
	}

	s := newState()

	for _, inst := range instructions {
		s.step(inst, binary.ArchX86, 4)
	}

	// Verify that the stack pointer retains
	// the coordinate system created by alignment.
	sp := s.regs["rsp"]

	if sp.Kind != "stack-address" {
		t.Fatalf(
			"stack pointer not tracked: %+v",
			sp,
		)
	}

	if sp.Origin != "aligned-SP" {
		t.Fatalf(
			"incorrect stack origin: %+v",
			sp,
		)
	}

	if sp.StackOffset != -96 {
		t.Fatalf(
			"stack offset=%d, want -96",
			sp.StackOffset,
		)
	}

	// Verify the first i386 stack argument using
	// the actual production argument extractor.
	args := arguments(s, binary.ArchX86)

	if len(args) == 0 {
		t.Fatal("no i386 call arguments")
	}

	arg := args[0]

	if arg.Position != 1 {
		t.Fatalf(
			"argument position=%d, want 1",
			arg.Position,
		)
	}

	if arg.Location != "[esp+0]" {
		t.Fatalf(
			"argument location=%q, want [esp+0]",
			arg.Location,
		)
	}

	value := arg.Value

	// The input destination is:
	//
	// aligned-SP - 96 + 28 = aligned-SP - 68
	if value.Kind != "stack-address" ||
		value.Origin != "aligned-SP" ||
		value.StackOffset != -68 {
		t.Fatalf(
			"unexpected gets argument: %+v",
			value,
		)
	}

	// Verify that the checked stack location
	// was initialized to zero.
	//
	// aligned-SP - 96 + 92 = aligned-SP - 4
	checkedOffset := sp.StackOffset + 0x5c

	checkedValue, ok := s.stack[checkedOffset]
	if !ok {
		t.Fatalf(
			"checked stack location missing at %d",
			checkedOffset,
		)
	}

	if checkedValue.Kind != "constant" ||
		checkedValue.Number != 0 {
		t.Fatalf(
			"checked location not initialized to zero: %+v",
			checkedValue,
		)
	}

	// Both addresses use the same aligned-SP origin.
	// Their separation must be exactly 64 bytes.
	separation := checkedOffset - value.StackOffset

	if separation != 64 {
		t.Fatalf(
			"stack separation=%d, want 64",
			separation,
		)
	}
}
