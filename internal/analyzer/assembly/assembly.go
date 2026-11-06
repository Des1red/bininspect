package assembly

import (
	"regexp"
	"strconv"
	"strings"

	"bininspect/internal/analyzer/shared"
	"bininspect/internal/models"
)

var (
	addressPattern = regexp.MustCompile(
		`^\s*([0-9a-fA-F]+):\s*(.*)$`,
	)

	bytePattern = regexp.MustCompile(
		`^(?:(?:[0-9a-fA-F]{2}|[0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s+)+`,
	)

	targetSymbol = regexp.MustCompile(`<([^>]+)>`)

	targetAddress = regexp.MustCompile(
		`^(?:0x)?[0-9a-fA-F]+$`,
	)
)

func Analyze(architecture string) models.AssemblyAnalysis {
	result := models.AssemblyAnalysis{
		Architecture: architecture,
	}

	var currentFunction string

	for _, line := range strings.Split(
		models.Knowledge.Assembly, "\n",
	) {
		if _, name, ok := shared.FunctionHeader(line); ok {
			currentFunction = name
			continue
		}

		inst, ok := parseInstruction(line)
		if !ok {
			continue
		}

		inst.Function = currentFunction
		inst.Kind = classify(inst.Mnemonic, inst.Operands)

		switch inst.Kind {
		case "call":
			result.Calls++

		case "branch":
			result.Branches++

		case "return":
			result.Returns++
		}

		if inst.Kind == "call" || inst.Kind == "branch" {
			inst.Target, inst.Indirect = resolveTarget(
				inst.Mnemonic, inst.Operands,
			)
		}

		if size, ok := stackAllocation(inst); ok {
			result.StackAllocations = append(
				result.StackAllocations,
				models.StackAllocation{
					Address:  inst.Address,
					Function: currentFunction,
					Size:     size,
				},
			)
		}

		result.Instructions = append(
			result.Instructions, inst,
		)
	}

	return result
}

func parseInstruction(line string) (models.Instruction, bool) {
	var inst models.Instruction

	match := addressPattern.FindStringSubmatch(line)
	if match == nil {
		return inst, false
	}

	inst.Address = match[1]
	body := strings.TrimSpace(match[2])

	if body == "" {
		return inst, false
	}
	if targetAddress.MatchString(body) {
		return inst, false
	}
	// GNU objdump normally separates bytes and instructions
	// using tab characters.
	parts := strings.Split(body, "\t")

	if len(parts) > 1 {
		inst.Bytes = strings.TrimSpace(
			strings.Join(parts[:len(parts)-1], " "),
		)
		body = strings.TrimSpace(parts[len(parts)-1])
	} else {
		// LLVM output may separate bytes using spaces.
		raw := bytePattern.FindString(body)

		if raw != "" {
			inst.Bytes = strings.TrimSpace(raw)
			body = strings.TrimSpace(
				strings.TrimPrefix(body, raw),
			)
		}
	}

	fields := strings.Fields(body)
	if len(fields) == 0 {
		return inst, false
	}

	inst.Mnemonic = strings.ToLower(fields[0])

	if len(fields) > 1 {
		inst.Operands = strings.TrimSpace(
			strings.TrimPrefix(body, fields[0]),
		)
	}

	return inst, true
}

func classify(mnemonic, operands string) string {
	op := strings.ToLower(mnemonic)
	args := strings.ToLower(strings.TrimSpace(operands))

	switch {
	case op == "ret", op == "retq",
		op == "retl", op == "retab",
		op == "retaa", op == "iret",
		op == "iretd", op == "iretq",
		op == "eret":
		return "return"

	case op == "bx" && (args == "lr" || args == "r14"):
		return "return"

	case op == "jr" && args == "ra":
		return "return"

	case op == "jalr" &&
		(args == "x0, 0(ra)" || args == "zero, 0(ra)"):
		return "return"

	case op == "call", op == "callq",
		op == "calll", op == "lcall",
		op == "bl", op == "blx", op == "blr":
		return "call"

	case op == "jal":
		if strings.HasPrefix(args, "x0,") ||
			strings.HasPrefix(args, "zero,") {
			return "branch"
		}
		return "call"

	case op == "jalr":
		if strings.HasPrefix(args, "x0,") ||
			strings.HasPrefix(args, "zero,") {
			return "branch"
		}
		return "call"

	case op == "jmp", op == "jmpq",
		op == "jmpl", op == "ljmp",
		op == "b", op == "br",
		op == "bx", op == "bra":
		return "branch"

	case strings.HasPrefix(op, "j"):
		return "branch"

	case strings.HasPrefix(op, "b.") ||
		op == "cbz" || op == "cbnz" ||
		op == "tbz" || op == "tbnz":
		return "branch"

	case op == "beq", op == "bne",
		op == "blt", op == "bge",
		op == "bltu", op == "bgeu":
		return "branch"

	case op == "push", op == "pop":
		return "stack"

	case op == "cmp", op == "test",
		op == "cmn", op == "tst":
		return "compare"

	case op == "mov", op == "movz",
		op == "movk", op == "lea",
		op == "ldr", op == "ldp",
		op == "ld", op == "lw",
		op == "str", op == "stp",
		op == "sd", op == "sw":
		return "memory"

	case op == "add", op == "sub",
		op == "addi", op == "and",
		op == "orr", op == "or",
		op == "xor", op == "eor",
		op == "mul", op == "imul":
		return "arithmetic"

	case op == "nop", op == "hint":
		return "nop"

	case op == "syscall", op == "sysenter",
		op == "svc", op == "ecall",
		op == "int":
		return "system"

	default:
		return "other"
	}
}

func resolveTarget(mnemonic, operands string) (string, bool) {
	if match := targetSymbol.FindStringSubmatch(operands); match != nil {
		return match[1], false
	}

	args := strings.Split(operands, ",")
	if len(args) == 0 {
		return "", true
	}

	op := strings.ToLower(mnemonic)

	// Some RISC-V instructions specify a destination register
	// before the target.
	if (op == "jal" || op == "jalr") && len(args) > 1 {
		args = args[1:]
	}

	candidate := strings.TrimSpace(args[len(args)-1])
	candidate = strings.TrimPrefix(candidate, "#")
	candidate = strings.TrimPrefix(candidate, "*")

	if targetAddress.MatchString(candidate) {
		return candidate, false
	}

	return candidate, true
}

func stackAllocation(inst models.Instruction) (uint64, bool) {
	op := inst.Mnemonic
	args := strings.Split(inst.Operands, ",")

	switch op {
	case "sub":
		if len(args) == 2 {
			reg := strings.TrimSpace(args[0])

			if reg == "esp" || reg == "rsp" ||
				reg == "sp" {
				return parsePositive(args[1])
			}
		}

		if len(args) == 3 {
			dest := strings.TrimSpace(args[0])
			src := strings.TrimSpace(args[1])

			if dest == "sp" && src == "sp" {
				return parsePositive(args[2])
			}
		}

	case "addi":
		if len(args) == 3 {
			dest := strings.TrimSpace(args[0])
			src := strings.TrimSpace(args[1])

			if (dest == "sp" && src == "sp") ||
				(dest == "x2" && src == "x2") {

				value, err := strconv.ParseInt(
					strings.TrimSpace(args[2]), 0, 64,
				)

				if err == nil && value < 0 {
					return uint64(-value), true
				}
			}
		}
	}

	return 0, false
}

func parsePositive(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "#")
	value = strings.TrimPrefix(value, "$")

	n, err := strconv.ParseUint(value, 0, 64)

	return n, err == nil && n > 0
}
