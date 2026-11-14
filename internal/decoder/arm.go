package decoder

import (
	stdbinary "encoding/binary"
	"fmt"
	"strings"

	"bininspect/internal/binary"

	"golang.org/x/arch/arm/armasm"
)

func decodeARM(
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

	native, err := armasm.Decode(code, armasm.ModeARM)
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
		Mode:     ModeARM,
	}

	for _, arg := range native.Args {
		if arg == nil {
			break
		}

		operand := Operand{Kind: OperandOpaque, Text: arg.String()}

		switch v := arg.(type) {
		case armasm.Reg:
			operand.Kind = OperandRegister
			operand.Register = v.String()

		case armasm.Imm:
			operand.Kind = OperandImmediate
			operand.Immediate = int64(v)

		case armasm.ImmAlt:
			operand.Kind = OperandImmediate
			operand.Immediate = int64(v.Imm())

		case armasm.Mem:
			if v.Sign == 0 {
				operand.Kind = OperandMemory
				operand.Memory.Base = v.Base.String()
				operand.Memory.Displacement = int64(v.Offset)

				switch v.Mode {
				case armasm.AddrOffset:
					operand.Memory.Addressing = "offset"

				case armasm.AddrPreIndex:
					operand.Memory.Addressing = "pre-index"

				case armasm.AddrPostIndex:
					operand.Memory.Addressing = "post-index"

				default:
					operand.Kind = OperandOpaque
				}
			}

			// Indexed/shifted registers are deliberately opaque
			// until their full semantics are represented.
		case armasm.PCRel:
			operand.Kind = OperandRelative
			operand.Relative = int64(v)
		}

		inst.Operands = append(inst.Operands, operand)
	}

	op := strings.ToUpper(inst.Mnemonic)

	switch {
	case strings.HasPrefix(op, "BLX"),
		strings.HasPrefix(op, "BL"):
		inst.Flow = FlowCall

	case op == "BX", strings.HasPrefix(op, "BX_"):
		inst.Flow = FlowJump

	case op == "B" || strings.HasPrefix(op, "B_"):
		inst.Flow = FlowJump
		if op != "B" {
			inst.Flow = FlowConditional
		}

	case op == "SVC" || strings.HasPrefix(op, "SVC_"):
		inst.Flow = FlowSystem

	case op == "BKPT" || strings.HasPrefix(op, "BKPT_"):
		inst.Flow = FlowTrap
	}

	if (op == "BX" || strings.HasPrefix(op, "BX_")) &&
		len(inst.Operands) > 0 {

		reg := inst.Operands[0].Register

		if reg == "R14" || reg == "LR" {
			inst.Flow = FlowReturn
		}
	}

	// The ARM ARM branch immediate uses a signed imm24 << 2,
	// relative to the instruction address + 8.
	encoding := stdbinary.LittleEndian.Uint32(code)
	if inst.Flow == FlowCall ||
		inst.Flow == FlowJump ||
		inst.Flow == FlowConditional {
		if encoding&0x0e000000 == 0x0a000000 &&
			encoding>>28 != 0xf {

			imm24 := int32(encoding & 0x00ffffff)
			imm24 = (imm24 << 8) >> 8

			target := uint64(
				int64(address) + 8 + int64(imm24)*4,
			)

			inst.Target = uint64(uint32(target))
			inst.HasTarget = true
		} else if len(inst.Operands) > 0 {
			switch inst.Operands[0].Kind {
			case OperandRegister, OperandMemory:
				inst.Indirect = true
			}
		}
	}

	return inst, nil
}
