package decoder

import (
	"fmt"

	"bininspect/internal/binary"

	"golang.org/x/arch/arm64/arm64asm"
)

func decodeARM64(
	src []byte,
	address uint64,
	endian binary.Endianness,
) (Instruction, error) {
	if len(src) < 4 {
		return Instruction{}, ErrTruncatedInstruction
	}

	code := append([]byte(nil), src[:4]...)

	if endian == binary.BigEndian {
		code[0], code[3] = code[3], code[0]
		code[1], code[2] = code[2], code[1]
	}

	native, err := arm64asm.Decode(code)
	if err != nil {
		return Instruction{}, fmt.Errorf(
			"%w at %#x: %v",
			ErrInvalidInstruction, address, err,
		)
	}

	inst := Instruction{
		Address:  address,
		Size:     4,
		Bytes:    append([]byte(nil), src[:4]...),
		Mnemonic: native.Op.String(),
	}

	for _, arg := range native.Args {
		if arg == nil {
			break
		}

		operand := Operand{
			Kind: OperandOpaque,
			Text: arg.String(),
		}

		switch value := arg.(type) {
		case arm64asm.Reg:
			operand.Kind = OperandRegister
			operand.Register = value.String()

		case arm64asm.RegSP:
			operand.Kind = OperandRegister
			operand.Register = value.String()

		case arm64asm.Imm:
			operand.Kind = OperandImmediate
			operand.Immediate = int64(value.Imm)

		case arm64asm.Imm64:
			operand.Kind = OperandImmediate
			operand.Immediate = int64(value.Imm)

		case arm64asm.PCRel:
			operand.Kind = OperandRelative
			operand.Relative = int64(value)

		case arm64asm.MemImmediate:
			operand, err = arm64MemoryOperand(value)
			if err != nil {
				return Instruction{}, fmt.Errorf(
					"AArch64 memory at %#x: %w",
					address, err,
				)
			}

			// Complex register-extended memory operands are
			// left opaque until their full addressing semantics
			// are represented by the shared operand model.
		}

		inst.Operands = append(inst.Operands, operand)
	}

	switch native.Op {
	case arm64asm.BL, arm64asm.BLR:
		inst.Flow = FlowCall

	case arm64asm.B, arm64asm.BR:
		inst.Flow = FlowJump

	case arm64asm.CBZ, arm64asm.CBNZ,
		arm64asm.TBZ, arm64asm.TBNZ:
		inst.Flow = FlowConditional

	case arm64asm.RET, arm64asm.ERET:
		inst.Flow = FlowReturn

	case arm64asm.SVC, arm64asm.HVC, arm64asm.SMC:
		inst.Flow = FlowSystem

	case arm64asm.BRK, arm64asm.HLT:
		inst.Flow = FlowTrap
	}

	if native.Op == arm64asm.B {
		for _, arg := range native.Args {
			if _, ok := arg.(arm64asm.Cond); ok {
				inst.Flow = FlowConditional
				break
			}
		}
	}

	if inst.Flow == FlowCall ||
		inst.Flow == FlowJump ||
		inst.Flow == FlowConditional {

		for i := range inst.Operands {
			operand := &inst.Operands[i]

			if operand.Kind != OperandRelative {
				continue
			}

			target := address + uint64(operand.Relative)

			operand.Target = target
			operand.HasTarget = true

			inst.Target = target
			inst.HasTarget = true
			break
		}

		if !inst.HasTarget {
			switch native.Op {
			case arm64asm.BR, arm64asm.BLR:
				inst.Indirect = true
			}
		}
	}

	return inst, nil
}
