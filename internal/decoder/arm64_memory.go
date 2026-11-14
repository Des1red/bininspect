package decoder

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

func arm64MemoryOperand(
	value arm64asm.MemImmediate,
) (Operand, error) {
	return parseARM64Memory(
		value.String(),
		value.Base.String(),
		value.Mode,
	)
}

func parseARM64Memory(
	text, base string,
	mode arm64asm.AddrMode,
) (Operand, error) {
	text = strings.TrimSpace(text)

	if !strings.HasPrefix(text, "[") {
		return Operand{}, fmt.Errorf(
			"invalid AArch64 memory operand %q", text,
		)
	}

	closeIndex := strings.IndexByte(text, ']')
	if closeIndex < 0 {
		return Operand{}, fmt.Errorf(
			"unterminated AArch64 memory operand %q", text,
		)
	}

	inside := strings.TrimSpace(text[1:closeIndex])
	tail := strings.TrimSpace(text[closeIndex+1:])

	fields := strings.Split(inside, ",")

	if len(fields) == 0 || len(fields) > 2 ||
		!strings.EqualFold(strings.TrimSpace(fields[0]), base) {
		return Operand{}, fmt.Errorf(
			"invalid AArch64 memory base in %q", text,
		)
	}

	memory := Memory{
		Base: base,
	}

	parseImmediate := func(value string) (int64, error) {
		value = strings.TrimSpace(value)

		if !strings.HasPrefix(value, "#") {
			return 0, fmt.Errorf(
				"expected immediate, got %q", value,
			)
		}

		value = strings.TrimPrefix(value, "#")

		// arm64asm prints memory displacements in decimal.
		return strconv.ParseInt(value, 10, 64)
	}

	switch mode {
	case arm64asm.AddrOffset:
		memory.Addressing = "offset"

		if tail != "" {
			return Operand{}, fmt.Errorf(
				"unexpected offset suffix %q", tail,
			)
		}

		if len(fields) == 2 {
			value, err := parseImmediate(fields[1])
			if err != nil {
				return Operand{}, err
			}
			memory.Displacement = value
		}

	case arm64asm.AddrPreIndex:
		memory.Addressing = "pre-index"

		if tail != "!" || len(fields) != 2 {
			return Operand{}, fmt.Errorf(
				"invalid pre-index operand %q", text,
			)
		}

		value, err := parseImmediate(fields[1])
		if err != nil {
			return Operand{}, err
		}

		memory.Displacement = value

	case arm64asm.AddrPostIndex:
		memory.Addressing = "post-index"

		if len(fields) != 1 ||
			!strings.HasPrefix(tail, ",") {
			return Operand{}, fmt.Errorf(
				"invalid post-index operand %q", text,
			)
		}

		value, err := parseImmediate(tail[1:])
		if err != nil {
			return Operand{}, err
		}

		memory.Displacement = value

	case arm64asm.AddrPostReg:
		memory.Addressing = "post-register"

		if len(fields) != 1 ||
			!strings.HasPrefix(tail, ",") {
			return Operand{}, fmt.Errorf(
				"invalid post-register operand %q", text,
			)
		}

		memory.Index = strings.TrimSpace(tail[1:])
		if memory.Index == "" {
			return Operand{}, fmt.Errorf(
				"missing post-index register",
			)
		}

	default:
		return Operand{}, fmt.Errorf(
			"unsupported AArch64 addressing mode",
		)
	}

	return Operand{
		Kind:   OperandMemory,
		Memory: memory,
		Text:   text,
	}, nil
}
