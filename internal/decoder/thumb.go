package decoder

import (
	"fmt"
	"strconv"
	"strings"

	"bininspect/internal/binary"

	"github.com/loov/disasm/thumbasm"
)

func decodeThumb(
	src []byte,
	address uint64,
	endian binary.Endianness,
) (Instruction, error) {
	result, err := thumbDecode(src, address, endian, true)
	if err != nil {
		return Instruction{}, err
	}
	return result[0], nil
}

func decodeThumbRange(
	src []byte,
	address uint64,
	endian binary.Endianness,
) ([]Instruction, error) {
	return thumbDecode(src, address, endian, false)
}

func thumbDecode(
	src []byte,
	address uint64,
	endian binary.Endianness,
	single bool,
) ([]Instruction, error) {
	// thumbasm decodes little-endian instruction bytes.
	// Do not silently guess the instruction byte order
	// for big-endian ARM files.
	if endian != binary.LittleEndian {
		return nil, fmt.Errorf(
			"%w: big-endian Thumb byte order",
			ErrUnsupportedArchitecture,
		)
	}

	if address%2 != 0 {
		return nil, fmt.Errorf(
			"%w: unaligned Thumb address %#x",
			ErrInvalidRange, address,
		)
	}

	if len(src) < 2 {
		return nil, ErrTruncatedInstruction
	}

	if !single && len(src)%2 != 0 {
		return nil, ErrTruncatedInstruction
	}

	var decoder thumbasm.Decoder
	var result []Instruction

	for offset := 0; offset < len(src); {
		pc := address + uint64(offset)

		raw, err := decoder.Decode(src[offset:], pc)
		if err != nil {
			return result, fmt.Errorf(
				"%w at %#x: %v",
				ErrInvalidInstruction, pc, err,
			)
		}

		if (raw.Len != 2 && raw.Len != 4) ||
			raw.Len > len(src)-offset {
			return result, fmt.Errorf(
				"%w at %#x: bad Thumb instruction length",
				ErrInvalidInstruction, pc,
			)
		}

		inst := thumbInstruction(
			raw,
			src[offset:offset+raw.Len],
			pc,
		)

		result = append(result, inst)
		offset += raw.Len

		if single {
			return result, nil
		}
	}

	return result, nil
}

func thumbInstruction(
	raw thumbasm.Inst,
	bytes []byte,
	address uint64,
) Instruction {
	text := strings.TrimSpace(raw.Text)
	mnemonic := strings.ToUpper(raw.Mnemonic)

	operands := ""

	fields := strings.Fields(text)

	if len(fields) > 0 {
		mnemonic = strings.ToUpper(fields[0])
		operands = strings.TrimSpace(
			text[len(fields[0]):],
		)
	}

	inst := Instruction{
		Address:  address,
		Size:     uint8(raw.Len),
		Bytes:    append([]byte(nil), bytes...),
		Mnemonic: mnemonic,
		Mode:     ModeThumb,
	}

	if operands != "" {
		for _, part := range thumbSplitOperands(operands) {
			inst.Operands = append(
				inst.Operands,
				thumbOperand(part),
			)
		}
	}

	base := strings.ToUpper(raw.Mnemonic)

	switch {
	case base == "BX" && thumbHasRegister(inst, "LR"):
		inst.Flow = FlowReturn

	case base == "POP" && thumbContainsPC(operands):
		inst.Flow = FlowReturn

	case raw.Call:
		inst.Flow = FlowCall

	case raw.Branch:
		inst.Flow = FlowJump
		if thumbConditional(mnemonic) {
			inst.Flow = FlowConditional
		}

	case base == "BX" || base == "BLX":
		inst.Flow = FlowJump
		inst.Indirect = true
		if base == "BLX" {
			inst.Flow = FlowCall
		}

	case base == "SVC":
		inst.Flow = FlowSystem

	case base == "BKPT" || base == "UDF":
		inst.Flow = FlowTrap
	}

	if raw.HasTarget &&
		(inst.Flow == FlowCall ||
			inst.Flow == FlowJump ||
			inst.Flow == FlowConditional) {
		inst.Target = raw.Target
		inst.HasTarget = true
		inst.Indirect = false
	}

	return inst
}

func thumbConditional(mnemonic string) bool {
	name := strings.TrimSuffix(
		strings.ToUpper(mnemonic), ".W",
	)

	if name == "CBZ" || name == "CBNZ" {
		return true
	}

	if !strings.HasPrefix(name, "B") {
		return false
	}

	switch strings.TrimPrefix(name, "B") {
	case "EQ", "NE", "CS", "CC", "HS", "LO",
		"MI", "PL", "VS", "VC", "HI", "LS",
		"GE", "LT", "GT", "LE":
		return true
	}

	return false
}

func thumbHasRegister(
	inst Instruction,
	register string,
) bool {
	for _, operand := range inst.Operands {
		if operand.Kind == OperandRegister &&
			operand.Register == register {
			return true
		}
	}
	return false
}

func thumbContainsPC(operands string) bool {
	s := strings.ToUpper(operands)

	start := strings.IndexByte(s, '{')
	end := strings.IndexByte(s, '}')

	if start == -1 || end <= start {
		return false
	}

	for _, part := range strings.Split(s[start+1:end], ",") {
		if strings.TrimSpace(part) == "PC" {
			return true
		}
	}

	return false
}

// Separate operands without splitting memory operands such as
// [R0, #4] or register lists such as {R4, PC}.
func thumbSplitOperands(s string) []string {
	var result []string
	var start, depth int

	for i, c := range s {
		switch c {
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		case ',':
			if depth == 0 {
				result = append(
					result,
					strings.TrimSpace(s[start:i]),
				)
				start = i + 1
			}
		}
	}

	result = append(
		result,
		strings.TrimSpace(s[start:]),
	)
	return result
}

func thumbOperand(s string) Operand {
	s = strings.TrimSpace(s)
	name := strings.ToUpper(s)

	if thumbRegister(name) {
		return Operand{
			Kind:     OperandRegister,
			Register: name,
		}
	}

	if strings.HasPrefix(s, "#") {
		if value, err := strconv.ParseInt(
			strings.TrimPrefix(s, "#"), 0, 64,
		); err == nil {
			return Operand{
				Kind:      OperandImmediate,
				Immediate: value,
			}
		}
	}

	// Only simple base+immediate addressing is promoted
	// to structured memory. Other addressing forms stay opaque.
	if strings.HasPrefix(s, "[") &&
		strings.HasSuffix(s, "]") {

		inside := s[1 : len(s)-1]
		parts := thumbSplitOperands(inside)

		if len(parts) >= 1 && len(parts) <= 2 {
			base := strings.ToUpper(
				strings.TrimSpace(parts[0]),
			)

			if thumbRegister(base) {
				memory := Memory{Base: base}

				if len(parts) == 1 {
					return Operand{
						Kind:   OperandMemory,
						Memory: memory,
					}
				}

				offset := strings.TrimSpace(parts[1])

				if strings.HasPrefix(offset, "#") {
					value, err := strconv.ParseInt(
						strings.TrimPrefix(offset, "#"),
						0, 64,
					)
					if err == nil {
						memory.Displacement = value

						return Operand{
							Kind:   OperandMemory,
							Memory: memory,
						}
					}
				}
			}
		}
	}

	return Operand{
		Kind: OperandOpaque,
		Text: s,
	}
}

func thumbRegister(s string) bool {
	switch s {
	case "SP", "LR", "PC", "IP", "FP":
		return true
	}

	if !strings.HasPrefix(s, "R") {
		return false
	}

	number, err := strconv.Atoi(s[1:])
	return err == nil && number >= 0 && number <= 15
}
