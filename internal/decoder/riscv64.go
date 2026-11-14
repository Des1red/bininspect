package decoder

import (
	"fmt"

	"golang.org/x/arch/riscv64/riscv64asm"
)

func decodeRISCV64(
	src []byte,
	address uint64,
) (Instruction, error) {
	if len(src) < 2 {
		return Instruction{}, ErrTruncatedInstruction
	}

	native, err := riscv64asm.Decode(src)
	if err != nil {
		return Instruction{}, fmt.Errorf(
			"%w at %#x: %v",
			ErrInvalidInstruction, address, err,
		)
	}

	if (native.Len != 2 && native.Len != 4) ||
		native.Len > len(src) {
		return Instruction{}, fmt.Errorf(
			"%w at %#x: invalid RISC-V length %d",
			ErrInvalidInstruction,
			address,
			native.Len,
		)
	}

	inst := Instruction{
		Address:  address,
		Size:     uint8(native.Len),
		Bytes:    append([]byte(nil), src[:native.Len]...),
		Mnemonic: native.Op.String(),
	}

	for _, raw := range native.Args {
		if raw == nil {
			break
		}

		operand := Operand{
			Kind: OperandOpaque,
			Text: raw.String(),
		}

		switch arg := raw.(type) {
		case riscv64asm.Reg:
			operand.Kind = OperandRegister
			operand.Register = arg.String()

		case riscv64asm.Simm:
			operand.Kind = OperandImmediate
			operand.Immediate = int64(arg.Imm)

		case riscv64asm.Uimm:
			operand.Kind = OperandImmediate
			operand.Immediate = int64(arg.Imm)

		case riscv64asm.RegOffset:
			operand.Kind = OperandMemory
			operand.Memory.Base = arg.OfsReg.String()
			operand.Memory.Displacement = int64(arg.Ofs.Imm)
		}

		inst.Operands = append(inst.Operands, operand)
	}

	switch native.Op {
	case riscv64asm.JAL:
		inst.Flow = FlowJump

		if len(inst.Operands) > 0 &&
			riscvLinkRegister(inst.Operands[0].Register) {
			inst.Flow = FlowCall
		}

	case riscv64asm.JALR:
		inst.Flow = FlowJump
		inst.Indirect = true

		if len(inst.Operands) > 0 &&
			riscvLinkRegister(inst.Operands[0].Register) {
			inst.Flow = FlowCall
		}

		if riscvReturn(inst) {
			inst.Flow = FlowReturn
			inst.Indirect = false
		}

	case riscv64asm.C_J:
		inst.Flow = FlowJump

	case riscv64asm.C_JALR:
		inst.Flow = FlowCall
		inst.Indirect = true

	case riscv64asm.C_JR:
		inst.Flow = FlowJump
		inst.Indirect = true

		if len(inst.Operands) != 0 &&
			riscvLinkRegister(inst.Operands[0].Register) {
			inst.Flow = FlowReturn
			inst.Indirect = false
		}

	case riscv64asm.BEQ, riscv64asm.BNE,
		riscv64asm.BLT, riscv64asm.BGE,
		riscv64asm.BLTU, riscv64asm.BGEU,
		riscv64asm.C_BEQZ, riscv64asm.C_BNEZ:
		inst.Flow = FlowConditional

	case riscv64asm.ECALL:
		inst.Flow = FlowSystem

	case riscv64asm.EBREAK, riscv64asm.C_EBREAK:
		inst.Flow = FlowTrap
	}

	if (inst.Flow == FlowCall ||
		inst.Flow == FlowJump ||
		inst.Flow == FlowConditional) &&
		!inst.Indirect {

		for i := len(inst.Operands) - 1; i >= 0; i-- {
			operand := &inst.Operands[i]

			if operand.Kind != OperandImmediate {
				continue
			}

			target := address + uint64(operand.Immediate)

			inst.Target = target
			inst.HasTarget = true
			operand.Target = target
			operand.HasTarget = true
			break
		}
	}

	return inst, nil
}

func riscvLinkRegister(name string) bool {
	return name == "x1" || name == "x5"
}

func riscvReturn(inst Instruction) bool {
	if len(inst.Operands) < 2 {
		return false
	}

	destination := inst.Operands[0]
	source := inst.Operands[1]

	return destination.Kind == OperandRegister &&
		destination.Register == "x0" &&
		source.Kind == OperandMemory &&
		riscvLinkRegister(source.Memory.Base) &&
		source.Memory.Displacement == 0
}
