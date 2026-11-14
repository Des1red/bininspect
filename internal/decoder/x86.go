package decoder

import (
	"errors"
	"fmt"

	"bininspect/internal/binary"

	"golang.org/x/arch/x86/x86asm"
)

func decodeX86(
	data []byte,
	address uint64,
	architecture binary.Architecture,
) (Instruction, error) {
	mode := 32

	if architecture == binary.ArchX8664 {
		mode = 64
	}

	native, err := x86asm.Decode(data, mode)
	if err != nil {
		kind := ErrInvalidInstruction

		if errors.Is(err, x86asm.ErrTruncated) {
			kind = ErrTruncatedInstruction
		}

		return Instruction{}, fmt.Errorf(
			"%w at %#x: %v",
			kind,
			address,
			err,
		)
	}

	if native.Len < 1 ||
		native.Len > 15 ||
		native.Len > len(data) ||
		native.Op == 0 {

		return Instruction{}, fmt.Errorf(
			"%w at %#x: unexpected decoder result",
			ErrInvalidInstruction,
			address,
		)
	}

	instruction := Instruction{
		Address:     address,
		Size:        uint8(native.Len),
		Bytes:       append([]byte(nil), data[:native.Len]...),
		Mnemonic:    native.Op.String(),
		Flow:        x86Flow(native.Op),
		AddressBits: uint8(native.AddrSize),
		OperandBits: uint8(native.DataSize),
	}

	for _, prefix := range native.Prefix {
		if prefix == 0 {
			break
		}

		instruction.Prefixes = append(
			instruction.Prefixes,
			prefix.String(),
		)
	}

	for _, raw := range native.Args {
		if raw == nil {
			break
		}

		var operand Operand

		switch arg := raw.(type) {
		case x86asm.Reg:
			operand.Kind = OperandRegister
			operand.Register = arg.String()

		case x86asm.Imm:
			operand.Kind = OperandImmediate
			operand.Immediate = int64(arg)

		case x86asm.Rel:
			operand.Kind = OperandRelative
			operand.Relative = int64(arg)
			operand.HasTarget = true

			next := address + uint64(native.Len)

			operand.Target = next +
				uint64(int64(arg))

			if mode == 32 {
				operand.Target = uint64(
					uint32(operand.Target),
				)
			}

		case x86asm.Mem:
			operand.Kind = OperandMemory

			operand.Memory = Memory{
				Segment: x86Register(arg.Segment),
				Base:    x86Register(arg.Base),
				Index:   x86Register(arg.Index),

				Scale:        arg.Scale,
				Displacement: arg.Disp,
				SizeBytes:    uint8(native.MemBytes),
			}

		default:
			return Instruction{}, fmt.Errorf(
				"%w at %#x: unsupported operand %T",
				ErrInvalidInstruction,
				address,
				raw,
			)
		}

		instruction.Operands = append(
			instruction.Operands,
			operand,
		)
	}

	// INT 3 is a breakpoint trap, not a normal system call.
	if native.Op == x86asm.INT &&
		len(instruction.Operands) > 0 &&
		instruction.Operands[0].Kind == OperandImmediate &&
		instruction.Operands[0].Immediate == 3 {

		instruction.Flow = FlowTrap
	}

	switch instruction.Flow {
	case FlowCall, FlowJump, FlowConditional:
		if len(instruction.Operands) == 0 {
			break
		}

		target := instruction.Operands[0]

		switch target.Kind {
		case OperandRelative:
			if target.HasTarget {
				instruction.Target = target.Target
				instruction.HasTarget = true
			}

		case OperandRegister, OperandMemory:
			instruction.Indirect = true
		}
	}

	return instruction, nil
}

func x86Register(reg x86asm.Reg) string {
	if reg == 0 {
		return ""
	}

	return reg.String()
}

func x86Flow(op x86asm.Op) FlowKind {
	switch op {
	case x86asm.CALL, x86asm.LCALL:
		return FlowCall

	case x86asm.JMP, x86asm.LJMP:
		return FlowJump

	case x86asm.JA, x86asm.JAE,
		x86asm.JB, x86asm.JBE,
		x86asm.JCXZ, x86asm.JE,
		x86asm.JECXZ, x86asm.JG,
		x86asm.JGE, x86asm.JL,
		x86asm.JLE, x86asm.JNE,
		x86asm.JNO, x86asm.JNP,
		x86asm.JNS, x86asm.JO,
		x86asm.JP, x86asm.JRCXZ,
		x86asm.JS, x86asm.LOOP,
		x86asm.LOOPE, x86asm.LOOPNE,
		x86asm.XBEGIN:

		return FlowConditional

	case x86asm.RET, x86asm.LRET,
		x86asm.IRET, x86asm.IRETD,
		x86asm.IRETQ:

		return FlowReturn

	case x86asm.SYSCALL, x86asm.SYSENTER,
		x86asm.INT, x86asm.INTO:

		return FlowSystem

	case x86asm.HLT, x86asm.UD2:
		return FlowTrap

	default:
		return FlowNone
	}
}
